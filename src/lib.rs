#![deny(clippy::all)]

use bytes::Bytes;
use flate2::read::GzDecoder;
use futures::StreamExt;
use miette::IntoDiagnostic;
use reqwest::Client;
use ssri::{Algorithm, Integrity, IntegrityOpts};
use std::io;
use std::path::Path;
use std::{
  collections::HashMap,
  error::Error,
  io::{Cursor, Read, Write},
  path::PathBuf,
  sync::OnceLock,
};
use tar::Archive;
use tokio::sync::mpsc;
use tokio::task;

const STORE_DIR: &str = "pnpm-store";

static CLIENT: OnceLock<Client> = OnceLock::new();

#[macro_use]
extern crate napi_derive;

#[napi]
pub async fn fetch_tarball(
  url: String,
  integrity: String,
) -> Result<HashMap<String, String>, napi::Error> {
  let parsed: Integrity = integrity.parse().map_err(|error| {
    napi::Error::new(
      napi::Status::InvalidArg,
      format!("Invalid integrity: {error}"),
    )
  })?;
  let index_location = content_path_from_hex(FileType::Index, parsed.to_hex().1.as_str());
  fetch_and_extract_streaming(&url, &integrity, index_location)
    .await
    .map_err(|error| napi::Error::new(napi::Status::GenericFailure, error.to_string()))
}

/// there are only 2 supported algorithms
/// sha1 and sha512
/// so we can be sure that if it doesn't start with sha1, it's going to have to be sha512
fn algorithm_from_integrity(expected_checksum: &str) -> Algorithm {
  if expected_checksum.starts_with("sha1") {
    Algorithm::Sha1
  } else {
    Algorithm::Sha512
  }
}

const DOWNLOAD_CHANNEL_CAPACITY: usize = 8;
async fn fetch_and_extract_streaming(
  url: &str,
  expected_integrity: &str,
  index_location: PathBuf,
) -> Result<HashMap<String, String>, Box<dyn Error + Send + Sync>> {
  let client = CLIENT.get_or_init(|| Client::builder().use_rustls_tls().build().unwrap());
  let response = client.get(url).send().await?;
  if !response.status().is_success() {
    return Err(format!("Failed to fetch tarball: {}", response.status()).into());
  }
  let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(DOWNLOAD_CHANNEL_CAPACITY);
  let extractor = task::spawn_blocking(move || {
    let reader = ChannelRead::new(rx);
    let gz = GzDecoder::new(reader);
    extract_tarball(gz)
  });

  let algorithm = algorithm_from_integrity(expected_integrity);
  let mut integrity_opts = IntegrityOpts::new().algorithm(algorithm);

  let mut stream = response.bytes_stream();

  while let Some(item) = stream.next().await {
    let chunk = match item {
      Ok(chunk) => chunk,
      Err(error) => {
        let _ = tx.send(Err(error.to_string())).await;
        return Err(Box::new(error));
      }
    };

    integrity_opts = integrity_opts.chain(&chunk);

    if tx.send(Ok(chunk)).await.is_err() {
      return Err("extractor stopped before download completed".into());
    }
  }
  drop(tx);
  let cas_file_map = extractor.await??;
  let calculated_integrity = integrity_to_string(integrity_opts.result(), algorithm);
  if calculated_integrity != expected_integrity {
    return Err("Tarball verification failed".into());
  }
  write_index(index_location.as_path(), &cas_file_map)?;
  Ok(cas_file_map)
}

fn integrity_to_string(integrity: Integrity, algo: Algorithm) -> String {
  if algo == Algorithm::Sha1 {
    format!("sha1-{}", integrity.to_hex().1)
  } else {
    integrity.to_string()
  }
}

pub fn extract_tarball<R: Read>(
  data: R,
) -> Result<HashMap<String, String>, Box<dyn Error + Send + Sync>> {
  // Generate the tarball archive given the decompressed bytes
  let mut node_archive = Archive::new(data);

  // extract to both the global store + node_modules (in the case of them using the pnpm linking algorithm)
  let mut cas_file_map: HashMap<String, String> = HashMap::new();

  for entry in node_archive.entries().into_diagnostic()? {
    let mut entry = entry.into_diagnostic()?;

    // Read the contents of the entry
    let mut buffer = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buffer).into_diagnostic()?;

    let entry_path = entry.path().unwrap();
    let components = entry_path.components();
    let cleaned_entry_path: PathBuf = components.skip(1).collect();

    let (_, hex_integrity) = IntegrityOpts::new()
      .algorithm(Algorithm::Sha512)
      .chain(&buffer)
      .result()
      .to_hex();
    let file_path =
      PathBuf::from(STORE_DIR).join(content_path_from_hex(FileType::NonExec, &hex_integrity));
    if !Path::exists(&file_path) {
      let parent_dir = file_path.parent().unwrap();
      std::fs::create_dir_all(parent_dir).unwrap();
      let mut file = std::fs::File::create(&file_path).unwrap();
      file.write_all(&buffer).into_diagnostic()?;
    }

    // // Write the contents of the entry into the content-addressable store located at `app.volt_dir`
    // // We get a hash of the file
    // let sri = cacache::write_hash_sync(STORE_DIR, &buffer).into_diagnostic()?;
    // cacache::get_sync(STORE_DIR, &sri).into_diagnostic()?;

    // Insert the name of the file and map it to the hash of the file
    cas_file_map.insert(
      cleaned_entry_path.to_str().unwrap().to_string(),
      file_path.to_string_lossy().into_owned(),
    );
  }

  Ok(cas_file_map)
}

fn write_index(
  index_location: &Path,
  cas_file_map: &HashMap<String, String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
  let dir = PathBuf::from(STORE_DIR).join(index_location);
  let parent_dir = dir.parent().unwrap();
  std::fs::create_dir_all(parent_dir).unwrap();
  std::fs::write(dir, serde_json::to_string(&cas_file_map)?)?;
  Ok(())
}

enum FileType {
  Exec,
  NonExec,
  Index,
}

fn content_path_from_hex(file_type: FileType, hex: &str) -> PathBuf {
  let mut p = PathBuf::new();
  p.push(&hex[0..2]);

  let extension = match file_type {
    FileType::Exec => "-exec",
    FileType::NonExec => "",
    FileType::Index => "-index.json",
  };

  p.push(&format!("{}{}", &hex[2..], extension));

  p
}

struct ChannelRead {
  rx: mpsc::Receiver<Result<Bytes, String>>,
  current: Cursor<Bytes>,
}

impl ChannelRead {
  fn new(rx: mpsc::Receiver<Result<Bytes, String>>) -> Self {
    Self {
      rx,
      current: Cursor::new(Bytes::new()),
    }
  }
}

impl Read for ChannelRead {
  /// Async channel read to Sync read
  fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    if self.current.position() == self.current.get_ref().len() as u64 {
      match self.rx.blocking_recv() {
        Some(Ok(chunk)) => {
          self.current = Cursor::new(chunk);
        }
        Some(Err(e)) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        None => {}
      }
    }
    self.current.read(buf)
  }
}

#[test]
fn create_content_path_from_hex() {
  assert_eq!(
    content_path_from_hex(
      FileType::NonExec,
      "1234567890abcdef1234567890abcdef12345678"
    ),
    PathBuf::from("12/34567890abcdef1234567890abcdef12345678")
  );
  assert_eq!(
    content_path_from_hex(FileType::Exec, "1234567890abcdef1234567890abcdef12345678"),
    PathBuf::from("12/34567890abcdef1234567890abcdef12345678-exec")
  );
  assert_eq!(
    content_path_from_hex(FileType::Index, "1234567890abcdef1234567890abcdef12345678"),
    PathBuf::from("12/34567890abcdef1234567890abcdef12345678-index.json")
  );
}
