#![deny(clippy::all)]

use reqwest::Client;
use tar::Archive;
use std::{
    error::Error,
    collections::HashMap,
    io::{Cursor, Read, Write},
    path::PathBuf,
};
use ssri::Integrity;
use miette::{IntoDiagnostic};

const STORE_DIR: &str = "pnpm-store";

#[macro_use]
extern crate napi_derive;

#[napi]
pub async fn fetch_tarball(url: String) -> String {
    let response = _fetch_tarball(&url).await.unwrap();
    let decompressed_response = decompress_gzip(&response).unwrap();
    let cas_file_map = extract_tarball(decompressed_response).unwrap();
    serde_json::to_string(&cas_file_map).unwrap()
}

async fn _fetch_tarball(url: &str) -> Result<bytes::Bytes, Box<dyn std::error::Error>> {
    let client = Client::new();
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
    data: Vec<u8>
) -> Result<HashMap<String, Integrity>, Box<dyn Error>> {
    // Generate the tarball archive given the decompressed bytes
    let mut node_archive = Archive::new(Cursor::new(data));

    // extract to both the global store + node_modules (in the case of them using the pnpm linking algorithm)
    let mut cas_file_map: HashMap<String, Integrity> = HashMap::new();

    for entry in node_archive.entries().into_diagnostic()? {
        let mut entry = entry.into_diagnostic()?;

        // Read the contents of the entry
        let mut buffer = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buffer).into_diagnostic()?;

        let entry_path = entry.path().unwrap();

        // Remove `package/` from `package/lib/index.js`
        let cleaned_entry_path_string = entry_path.strip_prefix("package/").unwrap();

        // Write the contents of the entry into the content-addressable store located at `app.volt_dir`
        // We get a hash of the file
        let sri = cacache::write_hash_sync(STORE_DIR, &buffer).into_diagnostic()?;

        // Insert the name of the file and map it to the hash of the file
        cas_file_map.insert(cleaned_entry_path_string.to_str().unwrap().to_string(), sri);
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

