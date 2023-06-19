#![deny(clippy::all)]

use reqwest::Client;
use tar::Archive;
use std::{
    error::Error,
    collections::HashMap,
    io::{Cursor, Read, Write},
    path::PathBuf,
    sync::OnceLock,
};
use ssri::Integrity;
use miette::{IntoDiagnostic};
use sanitize_filename::sanitize;

const STORE_DIR: &str = "pnpm-store";

static CLIENT: OnceLock<Client> = OnceLock::new();

#[macro_use]
extern crate napi_derive;

#[napi]
pub async fn fetch_tarball(url: String) -> HashMap<String, String> {
    let response = _fetch_tarball(&url).await.unwrap();
    let decompressed_response = decompress_gzip(&response).unwrap();
    let target_dir = sanitize(&url);
    let cas_file_map = extract_tarball(&target_dir, decompressed_response).unwrap();
    cas_file_map
}

async fn _fetch_tarball(url: &str) -> Result<bytes::Bytes, Box<dyn std::error::Error>> {
    let client = CLIENT.get_or_init(Client::new);
    let res = client.get(url)
        .send()
        .await?;
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
    target_dir: &str,
    data: Vec<u8>
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

        // Remove `package/` from `package/lib/index.js`
        let cleaned_entry_path_string = entry_path.strip_prefix("package/").unwrap();

        let dir = PathBuf::from(STORE_DIR).join(target_dir);
        std::fs::create_dir_all(&dir).into_diagnostic()?;
        let file_path = PathBuf::from(STORE_DIR)
            .join(target_dir)
            .join(sanitize(cleaned_entry_path_string.to_string_lossy().as_ref()));
        let mut file = std::fs::File::create(&file_path).unwrap();

        file.write_all(&buffer).into_diagnostic()?;

        // // Write the contents of the entry into the content-addressable store located at `app.volt_dir`
        // // We get a hash of the file
        // let sri = cacache::write_hash_sync(STORE_DIR, &buffer).into_diagnostic()?;
        // cacache::get_sync(STORE_DIR, &sri).into_diagnostic()?;

        // Insert the name of the file and map it to the hash of the file
        cas_file_map.insert(cleaned_entry_path_string.to_str().unwrap().to_string(), file_path.to_string_lossy().into_owned());
    }

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
        content_path_from_hex(FileType::NonExec, "1234567890abcdef1234567890abcdef12345678"),
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

