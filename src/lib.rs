#![deny(clippy::all)]

use miette::IntoDiagnostic;
use reqwest::Client;
use ssri::{Algorithm, Integrity, IntegrityOpts};
use std::path::Path;
use std::{
  collections::HashMap,
  error::Error,
  io::{Cursor, Read, Write},
  path::PathBuf,
  sync::OnceLock,
};
use tar::Archive;
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
  let response = _fetch_tarball(&url).await.unwrap();
  let (verified, _checksum) = verify_checksum(&response, &integrity).unwrap();
  if !verified {
    return Err(napi::Error::new(
      napi::Status::GenericFailure,
      "Tarball verification failed",
    ));
  }
  task::spawn_blocking(move || {
    let decompressed_response = decompress_gzip(&response).unwrap();
    let parsed: Integrity = integrity.parse().unwrap();
    let index_location_pb = content_path_from_hex(FileType::Index, parsed.to_hex().1.as_str());
    let cas_file_map = extract_tarball(index_location_pb.as_path(), decompressed_response).unwrap();
    Ok(cas_file_map)
  })
  .await
  .unwrap()
}

pub fn verify_checksum(
  response: &bytes::Bytes,
  expeced_checksum: &str,
) -> Result<(bool, Option<String>), Box<dyn std::error::Error>> {
  // begin
  // there are only 2 supported algorithms
  // sha1 and sha512
  // so we can be sure that if it doesn't start with sha1, it's going to have to be sha512

  let algorithm = if expeced_checksum.starts_with("sha1") {
    Algorithm::Sha1
  } else {
    Algorithm::Sha512
  };

  let calculated_checksum = calc_hash(response, algorithm)?;

  if calculated_checksum == expeced_checksum {
    Ok((true, None))
  } else {
    Ok((false, Some(calculated_checksum)))
  }
}

fn calc_hash(
  data: &bytes::Bytes,
  algorithm: Algorithm,
) -> Result<String, Box<dyn std::error::Error>> {
  let integrity = if algorithm == Algorithm::Sha1 {
    let hash = ssri::IntegrityOpts::new()
      .algorithm(Algorithm::Sha1)
      .chain(&data)
      .result();
    format!("sha1-{}", hash.to_hex().1)
  } else {
    ssri::IntegrityOpts::new()
      .algorithm(Algorithm::Sha512)
      .chain(&data)
      .result()
      .to_string()
  };
  Ok(integrity)
}

async fn _fetch_tarball(url: &str) -> Result<bytes::Bytes, Box<dyn std::error::Error>> {
  let client = CLIENT.get_or_init(|| Client::builder().use_rustls_tls().build().unwrap());
  let res = client.get(url).send().await?;
  Ok(res.bytes().await?)
}

pub fn decompress_gzip(gz_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
  // gzip RFC1952: a valid gzip file has an ISIZE field in the
  // footer, which is a little-endian u32 number representing the
  // decompressed size. This is ideal for libdeflate, which needs
  // preallocating the decompressed buffer.
  let isize = {
    let isize_start = gz_data.len() - 4;
    let isize_bytes: [u8; 4] = gz_data[isize_start..].try_into().into_diagnostic()?;
    u32::from_le_bytes(isize_bytes) as usize
  };

  let mut decompressor = libdeflater::Decompressor::new();

  let mut outbuf = vec![0; isize];
  decompressor
    .gzip_decompress(gz_data, &mut outbuf)
    .into_diagnostic()?;

  Ok(outbuf)
}

pub fn extract_tarball(
  index_location: &Path,
  data: Vec<u8>,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
  // Generate the tarball archive given the decompressed bytes
  let mut node_archive = Archive::new(Cursor::new(data));

  // extract to both the global store + node_modules (in the case of them using the pnpm linking algorithm)
  let mut cas_file_map: HashMap<String, String> = HashMap::new();

  for entry in node_archive.entries().into_diagnostic()? {
    let mut entry = entry.into_diagnostic()?;

    // Read the contents of the entry
    let mut buffer = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buffer).into_diagnostic()?;

    let entry_path = entry.path().unwrap();
    let components = entry_path.components();
    let cleaned_entry_path: std::path::PathBuf = components.skip(1).collect();

    let (_, hex_integrity) = IntegrityOpts::new()
      .algorithm(Algorithm::Sha512)
      .chain(&buffer)
      .result()
      .to_hex();
    let file_path =
      PathBuf::from(STORE_DIR).join(content_path_from_hex(FileType::NonExec, &hex_integrity));
    if !std::path::Path::exists(&file_path) {
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
  let dir = PathBuf::from(STORE_DIR).join(index_location);
  let parent_dir = dir.parent().unwrap();
  std::fs::create_dir_all(parent_dir).unwrap();
  std::fs::write(dir, serde_json::to_string(&cas_file_map)?)?;

  Ok(cas_file_map)
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
