use aes::Aes256;
use cbc::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit},
    Decryptor,
};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "decrypt-file",
    about = "AES-256-CBC decrypt a file produced by encrypt-file. Output saved as <input>.clear",
    disable_help_subcommand = true
)]
struct Args {
    /// Password used to derive the AES-256 key (SHA-256(password)).
    #[arg(value_name = "PASSWORD")]
    password: String,

    /// Path to the encrypted file (IV || ciphertext).
    #[arg(value_name = "FILE")]
    input: PathBuf,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let key = derive_key_from_password(&args.password);
    let output = derive_output_path(&args.input)?;

    let data = fs::read(&args.input)
        .map_err(|err| format!("failed to read input file {:?}: {err}", args.input))?;
    if data.len() < 16 {
        return Err("encrypted file is too short to contain an IV".into());
    }

    let (iv_bytes, ciphertext) = data.split_at(16);
    let cipher = Decryptor::<Aes256>::new_from_slices(&key, iv_bytes)
        .map_err(|err| format!("failed to initialize cipher: {err}"))?;

    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|err| format!("decryption failed: {err}"))?;

    fs::write(&output, plaintext)
        .map_err(|err| format!("failed to write output file {:?}: {err}", output))?;

    println!(
        "Decrypted {:?} -> {:?} ({} bytes -> {} bytes)",
        args.input,
        output,
        data.len(),
        plaintext.len()
    );

    Ok(())
}

fn derive_key_from_password(password: &str) -> [u8; 32] {
    let digest = Sha256::digest(password.as_bytes());
    digest.into()
}

fn derive_output_path(input: &PathBuf) -> Result<PathBuf, String> {
    let file_name = input
        .file_name()
        .ok_or_else(|| format!("input path {:?} has no file name", input))?;
    let mut dec_name: OsString = file_name.to_os_string();
    dec_name.push(".clear");
    let mut output = input.clone();
    output.set_file_name(dec_name);
    Ok(output)
}
