//! NalTool - Made by Kacefier - Version 4.1
//!
//! Copyright (C) 2026 Kacefier
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::io::{self, Write, Read, BufReader, BufWriter};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Instant, Duration};

use clap::{Parser, ArgAction};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use rand::rngs::OsRng as RandOsRng;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use flate2::Compression;
use flate2::write::{GzEncoder, GzDecoder};

// constants
const VERSION: &str = "4.1";
const MAGIC_HEADER: [u8; 4] = *b"NALT";
const HEADER_VERSION: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024;
const PBKDF2_ITERATIONS: u32 = 1_000_000;
const OBFUSCATE_SALT: &[u8] = b"NalTool_Kacefier_lZy@lOF04hqf?FM.waU^V[1ZW,e;TR5";

// command line arguments
#[derive(Parser)]
#[command(name = "naltool")]
#[command(about = "NalTool - Encryption and Decryption Tool", long_about = None)]
struct Cli {
    #[arg(short = 'v', long = "version", action = ArgAction::SetTrue, global = true)]
    version: bool,

    #[arg(short = 'i', long = "interface", action = ArgAction::SetTrue, global = true)]
    interface: bool,

    #[arg(short = 'h', long = "help", action = ArgAction::SetTrue, global = true)]
    help: bool,

    #[arg(short = 'e', long = "encrypt", global = true)]
    encrypt: Option<String>,

    #[arg(short = 'd', long = "decrypt", global = true)]
    decrypt: Option<String>,

    #[arg(long = "text", action = ArgAction::SetTrue, global = true)]
    text: bool,

    #[arg(short = 'k', long = "key", global = true)]
    key: Option<String>,

    #[arg(short = 'n', long = "nalkey", global = true)]
    nalkey: Option<String>,

    #[arg(long = "new", action = ArgAction::SetTrue, global = true)]
    new: bool,

    #[arg(short = 'c', long = "compress", action = ArgAction::SetTrue, global = true)]
    compress: bool,

    #[arg(short = 'l', long = "level", default_value = "3", global = true)]
    compress_level: u8,
}

// helper functions
#[inline]
fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }
    result
}

// Base91 encoding/decoding
const B91_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

#[inline]
fn b91encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut b = 0u32;
    let mut n = 0u32;
    let mut out = Vec::with_capacity((data.len() * 8 + 12) / 13 + 2);

    for &byte in data {
        b |= (byte as u32) << n;
        n += 8;
        if n > 13 {
            let v = b & 8191;
            if v > 88 {
                b >>= 13;
                n -= 13;
            } else {
                let v = b & 16383;
                b >>= 14;
                n -= 14;
                out.push(B91_ALPHABET[(v % 91) as usize]);
                out.push(B91_ALPHABET[(v / 91) as usize]);
                continue;
            }
            out.push(B91_ALPHABET[(v % 91) as usize]);
            out.push(B91_ALPHABET[(v / 91) as usize]);
        }
    }

    if n > 0 {
        out.push(B91_ALPHABET[(b % 91) as usize]);
        if n > 7 || b > 90 {
            out.push(B91_ALPHABET[(b / 91) as usize]);
        }
    }

    unsafe { String::from_utf8_unchecked(out) }
}

#[inline]
fn b91decode(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }

    let mut v = -1i32;
    let mut b = 0u32;
    let mut n = 0u32;
    let mut out = Vec::with_capacity(s.len() * 13 / 8 + 4);

    for &ch in s.as_bytes() {
        let c = match B91_ALPHABET.iter().position(|&x| x == ch) {
            Some(pos) => pos as u32,
            None => continue,
        };

        if v < 0 {
            v = c as i32;
        } else {
            v += (c * 91) as i32;
            b |= (v as u32) << n;
            n += if (v as u32 & 8191) > 88 { 13 } else { 14 };
            while n > 7 {
                out.push((b & 255) as u8);
                b >>= 8;
                n -= 8;
            }
            v = -1;
        }
    }

    if v != -1 {
        b |= (v as u32) << n;
        out.push((b & 255) as u8);
    }

    out
}

// cryptographic functions
fn derive_key(password: &str, salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let mut key = vec![0u8; dklen];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

// compression functions
fn compress_data(data: &[u8], level: u8) -> Result<Vec<u8>, String> {
    if data.len() < 512 {
        let mut result = Vec::with_capacity(data.len() + 1);
        result.push(0);
        result.extend_from_slice(data);
        return Ok(result);
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level as u32));
    encoder.write_all(data).map_err(|e| format!("compression error: {}", e))?;
    let compressed = encoder.finish().map_err(|e| format!("compression finalization error: {}", e))?;

    if compressed.len() < data.len() {
        let mut result = Vec::with_capacity(compressed.len() + 1);
        result.push(1);
        result.extend_from_slice(&compressed);
        Ok(result)
    } else {
        let mut result = Vec::with_capacity(data.len() + 1);
        result.push(0);
        result.extend_from_slice(data);
        Ok(result)
    }
}

fn decompress_data(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let flag = data[0];
    if flag == 0 {
        Ok(data[1..].to_vec())
    } else if flag == 1 {
        let mut decoder = GzDecoder::new(Vec::new());
        decoder.write_all(&data[1..]).map_err(|e| format!("decompression error: {}", e))?;
        let decompressed = decoder.finish().map_err(|e| format!("decompression finalization error: {}", e))?;
        Ok(decompressed)
    } else {
        Err(format!("invalid compression flag: {}, expected 0 or 1", flag))
    }
}

// text encryption with AES-GCM
pub fn encrypt_text(text: &str, password: &str) -> Result<String, String> {
    if text.is_empty() {
        return Err("text cannot be empty".to_string());
    }
    if password.is_empty() {
        return Err("key cannot be empty".to_string());
    }

    let plaintext = text.as_bytes();
    let compressed = compress_data(plaintext, 3)?;

    let mut rng = RandOsRng;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let enc_key = derive_key(password, &salt, PBKDF2_ITERATIONS, 32);

    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce, compressed.as_slice())
    .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    let mut combined = Vec::with_capacity(SALT_LEN + NONCE_LEN + TAG_LEN + ciphertext.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    Ok(b91encode(&combined))
}

// text decryption with AES-GCM
pub fn decrypt_text(encrypted: &str, password: &str) -> Result<String, String> {
    if encrypted.is_empty() {
        return Err("ciphertext cannot be empty".to_string());
    }
    if password.is_empty() {
        return Err("key cannot be empty".to_string());
    }

    let data = b91decode(encrypted);
    if data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(format!("data corrupted: length {} is less than minimum required {}", data.len(), SALT_LEN + NONCE_LEN + TAG_LEN));
    }

    let salt = &data[0..SALT_LEN];
    let nonce = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let enc_key = derive_key(password, salt, PBKDF2_ITERATIONS, 32);

    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher.decrypt(nonce, ciphertext)
    .map_err(|_| "decryption failed: wrong key or data corrupted. Please verify your key and ciphertext integrity.")?;

    let decompressed = decompress_data(&plaintext)?;

    String::from_utf8(decompressed).map_err(|e| format!("invalid UTF-8 output: {}", e))
}

// file encryption with AES-GCM and compression
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str, compress: bool, compress_level: u8) -> Result<(), String> {
    if !input_path.exists() {
        return Err(format!("input file not found: {}", input_path.display()));
    }
    if password.is_empty() {
        return Err("key cannot be empty".to_string());
    }

    let file_size = fs::metadata(input_path).map_err(|e| format!("failed to read file metadata: {}", e))?.len();
    if file_size == 0 {
        return Err("input file is empty, cannot encrypt".to_string());
    }

    let mut rng = RandOsRng;
    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut base_nonce);

    let enc_key = derive_key(password, &salt, PBKDF2_ITERATIONS, 32);

    let mut progress = ProgressBar::new(file_size, if compress { "Compressing & Encrypting" } else { "Encrypting" }, 40);

    let f_in = File::open(input_path).map_err(|e| format!("failed to open input file: {}", e))?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, f_in);
    let f_out = File::create(output_path).map_err(|e| format!("failed to create output file: {}", e))?;
    let mut writer = BufWriter::with_capacity(CHUNK_SIZE, f_out);

    writer.write_all(&MAGIC_HEADER).map_err(|e| format!("failed to write magic header: {}", e))?;
    writer.write_u8(HEADER_VERSION).map_err(|e| format!("failed to write version: {}", e))?;
    writer.write_all(&salt).map_err(|e| format!("failed to write salt: {}", e))?;
    writer.write_all(&base_nonce).map_err(|e| format!("failed to write base nonce: {}", e))?;

    let flags = if compress { 1u8 } else { 0u8 };
    writer.write_u8(flags).map_err(|e| format!("failed to write flags: {}", e))?;

    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_counter = 0u64;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut processed = 0u64;
    let mut chunk_index = 0u64;

    loop {
        let n = reader.read(&mut buffer).map_err(|e| format!("failed to read from input file: {}", e))?;
        if n == 0 {
            break;
        }

        let mut chunk = &buffer[..n];
        let compressed_chunk;

        if compress && n > 512 {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::new(compress_level as u32));
            encoder.write_all(chunk).map_err(|e| format!("compression error: {}", e))?;
            compressed_chunk = encoder.finish().map_err(|e| format!("compression finalization error: {}", e))?;
            if compressed_chunk.len() < n {
                chunk = &compressed_chunk;
            }
        }

        let mut chunk_nonce = base_nonce;
        let counter_bytes = nonce_counter.to_be_bytes();
        for i in 0..8 {
            chunk_nonce[i] ^= counter_bytes[i];
        }

        let nonce = Nonce::from_slice(&chunk_nonce);
        let ciphertext = cipher.encrypt(nonce, chunk)
        .map_err(|e| format!("AES-GCM encryption failed for chunk {}: {}", chunk_index, e))?;

        writer.write_u64::<BigEndian>(chunk_index).map_err(|e| format!("failed to write chunk index: {}", e))?;
        writer.write_u32::<BigEndian>(ciphertext.len() as u32).map_err(|e| format!("failed to write chunk length: {}", e))?;
        writer.write_all(&ciphertext).map_err(|e| format!("failed to write chunk data: {}", e))?;

        chunk_index += 1;
        nonce_counter += 1;

        if nonce_counter == u64::MAX {
            return Err("file too large: nonce counter overflow".to_string());
        }

        processed += n as u64;
        progress.set_progress(processed);
    }

    writer.flush().map_err(|e| format!("failed to flush output file: {}", e))?;
    progress.finish();
    Ok(())
}

// file decryption with AES-GCM
pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<(), String> {
    if !input_path.exists() {
        return Err(format!("input file not found: {}", input_path.display()));
    }
    if password.is_empty() {
        return Err("key cannot be empty".to_string());
    }

    let file_size = fs::metadata(input_path).map_err(|e| format!("failed to read file metadata: {}", e))?.len();
    let header_size = (4 + 1 + SALT_LEN + NONCE_LEN + 1) as u64;
    if file_size < header_size {
        return Err(format!("file corrupted: file size {} is less than minimum header size {}", file_size, header_size));
    }

    let f_in = File::open(input_path).map_err(|e| format!("failed to open input file: {}", e))?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, f_in);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(|e| format!("failed to read magic header: {}", e))?;
    if &magic != &MAGIC_HEADER {
        return Err(format!("file corrupted: invalid magic header, expected 'NALT' but got '{}'", String::from_utf8_lossy(&magic)));
    }

    let version = reader.read_u8().map_err(|e| format!("failed to read version: {}", e))?;
    if version != HEADER_VERSION {
        return Err(format!("unsupported version: {}, expected {}", version, HEADER_VERSION));
    }

    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt).map_err(|e| format!("failed to read salt: {}", e))?;

    let mut base_nonce = [0u8; NONCE_LEN];
    reader.read_exact(&mut base_nonce).map_err(|e| format!("failed to read base nonce: {}", e))?;

    let flags = reader.read_u8().map_err(|e| format!("failed to read flags: {}", e))?;
    let compressed = flags == 1;

    let enc_key = derive_key(password, &salt, PBKDF2_ITERATIONS, 32);

    let mut progress = ProgressBar::new(file_size, if compressed { "Decompressing & Decrypting" } else { "Decrypting" }, 40);

    let f_out = File::create(output_path).map_err(|e| format!("failed to create output file: {}", e))?;
    let mut writer = BufWriter::with_capacity(CHUNK_SIZE, f_out);

    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher = Aes256Gcm::new(key);
    let mut processed = 0u64;

    loop {
        let chunk_index = match reader.read_u64::<BigEndian>() {
            Ok(idx) => idx,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("failed to read chunk index: {}", e)),
        };

        let chunk_len = reader.read_u32::<BigEndian>()
        .map_err(|e| format!("failed to read chunk length: {}", e))? as usize;

        if chunk_len == 0 {
            return Err("file corrupted: chunk length is zero".to_string());
        }
        if chunk_len > CHUNK_SIZE + TAG_LEN {
            return Err(format!("file corrupted: chunk length {} exceeds maximum {}", chunk_len, CHUNK_SIZE + TAG_LEN));
        }

        let mut ciphertext = vec![0u8; chunk_len];
        reader.read_exact(&mut ciphertext).map_err(|e| format!("failed to read chunk data: {}", e))?;

        let mut chunk_nonce = base_nonce;
        let counter_bytes = chunk_index.to_be_bytes();
        for i in 0..8 {
            chunk_nonce[i] ^= counter_bytes[i];
        }

        let nonce = Nonce::from_slice(&chunk_nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| format!("AES-GCM decryption failed for chunk {}. Wrong key or data corrupted.", chunk_index))?;

        if compressed {
            let mut decoder = GzDecoder::new(Vec::new());
            decoder.write_all(&plaintext).map_err(|e| format!("decompression error for chunk {}: {}", chunk_index, e))?;
            let decompressed = decoder.finish().map_err(|e| format!("decompression finalization error for chunk {}: {}", chunk_index, e))?;
            writer.write_all(&decompressed).map_err(|e| format!("failed to write decompressed chunk {}: {}", chunk_index, e))?;
            processed += decompressed.len() as u64;
        } else {
            writer.write_all(&plaintext).map_err(|e| format!("failed to write chunk {}: {}", chunk_index, e))?;
            processed += plaintext.len() as u64;
        }

        progress.set_progress(processed);
    }

    writer.flush().map_err(|e| format!("failed to flush output file: {}", e))?;
    progress.finish();
    Ok(())
}

// Progress bar
pub struct ProgressBar {
    total: u64,
    desc: String,
    width: usize,
    current: u64,
    start_time: Instant,
    last_update: Instant,
    min_update_interval: Duration,
    finished: bool,
}

impl ProgressBar {
    pub fn new(total: u64, desc: &str, width: usize) -> Self {
        Self {
            total,
            desc: desc.to_string(),
            width,
            current: 0,
            start_time: Instant::now(),
            last_update: Instant::now(),
            min_update_interval: Duration::from_millis(100),
            finished: false,
        }
    }

    #[inline]
    pub fn update(&mut self, n: u64) {
        if self.finished {
            return;
        }
        self.current = std::cmp::min(self.current + n, self.total);
        self.render();
    }

    #[inline]
    pub fn set_progress(&mut self, value: u64) {
        if self.finished {
            return;
        }
        self.current = std::cmp::min(value, self.total);
        self.render();
    }

    pub fn finish(&mut self) {
        self.finished = true;
        self.current = self.total;
        self.render();
        println!();
    }

    fn render(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update) < self.min_update_interval && self.current < self.total {
            return;
        }
        self.last_update = now;

        let percent = self.current as f64 / self.total as f64;
        let filled_len = (self.width as f64 * percent) as usize;
        let bar: String = "█".repeat(filled_len) + &"░".repeat(self.width - filled_len);

        let elapsed = now.duration_since(self.start_time);
        let (speed, eta) = if self.current > 0 && self.current < self.total {
            let speed = self.current as f64 / elapsed.as_secs_f64();
            let eta = (self.total - self.current) as f64 / speed;
            (speed, eta)
        } else {
            (0.0, 0.0)
        };

        let percent_str = format!("{:>6.1}%", percent * 100.0);
        let time_str = if self.current < self.total {
            format!("[{}<{}]", format_duration(elapsed), format_duration(Duration::from_secs_f64(eta)))
        } else {
            format!("[{}]", format_duration(elapsed))
        };
        let speed_str = if speed > 0.0 {
            format!(" {}/s", format_size(speed as u64))
        } else {
            String::new()
        };

        print!("\r{}: {} {} {}{}", self.desc, bar, percent_str, time_str, speed_str);
        io::stdout().flush().unwrap();
    }
}

#[inline]
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:02}s", secs)
    } else if secs < 3600 {
        format!("{:02}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{:02}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[inline]
fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{:.1}B", size)
    } else if size < 1024 * 1024 {
        format!("{:.1}KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1}MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// NalKey functions
// NalKey is NOT encrypted, only obfuscated
fn simple_obfuscate(data: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = data.iter()
    .enumerate()
    .map(|(i, &byte)| byte ^ OBFUSCATE_SALT[i % OBFUSCATE_SALT.len()])
    .collect();
    result.reverse();
    result
}

fn simple_deobfuscate(data: &[u8]) -> Vec<u8> {
    let mut reversed = data.to_vec();
    reversed.reverse();
    reversed.iter()
    .enumerate()
    .map(|(i, &byte)| byte ^ OBFUSCATE_SALT[i % OBFUSCATE_SALT.len()])
    .collect()
}

pub fn generate_nalkey_at_path(original_key: &str, path: &Path) -> Result<(), String> {
    if original_key.is_empty() {
        return Err("key cannot be empty".to_string());
    }
    if path.is_dir() {
        return Err(format!("path is a directory, expected a file: {}", path.display()));
    }

    let key_bytes = original_key.as_bytes();
    let obfuscated = simple_obfuscate(key_bytes);
    let encoded_key = b91encode(&obfuscated);
    fs::write(path, encoded_key).map_err(|e| format!("failed to write NalKey file: {}", e))?;
    Ok(())
}

pub fn load_nalkey(nalkey_path: &Path) -> Result<String, String> {
    if !nalkey_path.exists() {
        return Err(format!("NalKey file not found: {}", nalkey_path.display()));
    }
    if nalkey_path.is_dir() {
        return Err(format!("path is a directory, expected a file: {}", nalkey_path.display()));
    }

    let encoded_key = fs::read_to_string(nalkey_path)
    .map_err(|e| format!("cannot read NalKey file: {}", e))?;
    let encoded_key = encoded_key.trim();
    if encoded_key.is_empty() {
        return Err("NalKey file is empty".to_string());
    }
    let obfuscated = b91decode(encoded_key);
    if obfuscated.is_empty() {
        return Err("NalKey file contains no valid data".to_string());
    }
    let key_bytes = simple_deobfuscate(&obfuscated);
    String::from_utf8(key_bytes).map_err(|e| format!("NalKey file corrupted: {}", e))
}

// password input with asterisk
#[cfg(unix)]
mod password_input {
    use std::io::{self, Write, Read};
    use std::fs::File;
    use termios::{tcsetattr, TCSADRAIN, ECHO, ICANON, Termios};
    use std::os::unix::io::AsRawFd;

    pub fn get_password(prompt: &str) -> Result<String, String> {
        let stdin = io::stdin();
        let fd = stdin.as_raw_fd();

        let mut termios = Termios::from_fd(fd).map_err(|e| format!("failed to get terminal settings: {}", e))?;
        let old = termios;
        termios.c_lflag &= !(ECHO | ICANON);
        tcsetattr(fd, TCSADRAIN, &termios).map_err(|e| format!("failed to set terminal settings: {}", e))?;

        print!("{}", prompt);
        io::stdout().flush().map_err(|e| format!("failed to flush stdout: {}", e))?;

        let mut password = String::new();
        let mut stdin_file = File::open("/dev/tty").map_err(|e| format!("failed to open TTY: {}", e))?;

        loop {
            let mut buf = [0u8; 1];
            match stdin_file.read_exact(&mut buf) {
                Ok(_) => {
                    let c = buf[0] as char;
                    if c == '\r' || c == '\n' {
                        println!();
                        break;
                    } else if c == '\x7f' || c == '\x08' {
                        if !password.is_empty() {
                            password.pop();
                            print!("\x08 \x08");
                            io::stdout().flush().map_err(|e| format!("failed to flush stdout: {}", e))?;
                        }
                    } else if c == '\x03' || c == '\x1b' {
                        tcsetattr(fd, TCSADRAIN, &old).map_err(|e| format!("failed to restore terminal settings: {}", e))?;
                        return Err("input interrupted by user".to_string());
                    } else {
                        password.push(c);
                        print!("*");
                        io::stdout().flush().map_err(|e| format!("failed to flush stdout: {}", e))?;
                    }
                }
                Err(_) => break,
            }
        }

        tcsetattr(fd, TCSADRAIN, &old).map_err(|e| format!("failed to restore terminal settings: {}", e))?;
        Ok(password)
    }
}

#[cfg(windows)]
mod password_input {
    use std::io::{self, Write};
    use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};
    use crossterm::cursor;
    use crossterm::execute;

    pub fn get_password(prompt: &str) -> Result<String, String> {
        // enable raw mode
        enable_raw_mode().map_err(|e| format!("failed to enable raw mode: {}", e))?;

        let mut stdout = io::stdout();
        execute!(stdout, cursor::Hide).map_err(|e| format!("failed to hide cursor: {}", e))?;

        print!("{}", prompt);
        stdout.flush().map_err(|e| format!("failed to flush stdout: {}", e))?;

        let mut password = Vec::new();
        let result = loop {
            match event::read().map_err(|e| format!("failed to read input: {}", e))? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    match key.code {
                        KeyCode::Enter => {
                            println!();
                            break Ok(String::from_utf8(password)
                            .map_err(|e| format!("invalid UTF-8: {}", e))?);
                        }
                        KeyCode::Backspace => {
                            if !password.is_empty() {
                                password.pop();
                                print!("\x08 \x08");
                                stdout.flush().map_err(|e| format!("failed to flush stdout: {}", e))?;
                            }
                        }
                        KeyCode::Char(c) => {
                            if c == '\x03' || c == '\x1b' {
                                break Err("input interrupted by user".to_string());
                            }
                            password.push(c as u8);
                            print!("*");
                            stdout.flush().map_err(|e| format!("failed to flush stdout: {}", e))?;
                        }
                        KeyCode::Delete => {
                            continue;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        };

        disable_raw_mode().map_err(|e| format!("failed to disable raw mode: {}", e))?;
        execute!(stdout, cursor::Show).map_err(|e| format!("failed to show cursor: {}", e))?;

        result
    }
}

#[cfg(not(any(windows, unix)))]
mod password_input {
    use std::io::{self, Write};

    pub fn get_password(prompt: &str) -> Result<String, String> {
        print!("{}", prompt);
        io::stdout().flush().map_err(|e| format!("failed to flush stdout: {}", e))?;
        let mut s = String::new();
        io::stdin().read_line(&mut s).map_err(|e| format!("failed to read input: {}", e))?;
        Ok(s.trim_end().to_string())
    }
}

fn get_password_with_asterisk(prompt: &str) -> Result<String, String> {
    password_input::get_password(prompt)
}

// get key from argument or prompt (interactive)
fn get_key_from_args(key: Option<String>, nalkey: Option<String>, prompt: &str) -> Result<String, String> {
    if let Some(k) = key {
        if k.contains(' ') {
            return Err("key cannot contain spaces. Please use a key without spaces or use a NalKey file.".to_string());
        }
        if k.is_empty() {
            return Err("key cannot be empty".to_string());
        }
        return Ok(k);
    }

    if let Some(path_str) = nalkey {
        let path = Path::new(&path_str);
        if !path.exists() {
            return Err(format!("NalKey file not found: {}", path_str));
        }
        return load_nalkey(path);
    }

    // No key provided, ask user
    eprintln!("{}", prompt);
    eprintln!("[1] Enter key manually");
    eprintln!("[2] Use NalKey file");

    print!("Select (1-2): ");
    io::stdout().flush().unwrap();
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();
    let choice = choice.trim();

    if choice == "1" {
        get_password_with_asterisk(prompt)
    } else if choice == "2" {
        print!("Enter NalKey file path: ");
        io::stdout().flush().unwrap();
        let mut path_str = String::new();
        io::stdin().read_line(&mut path_str).unwrap();
        let path_str = path_str.trim();
        let path = Path::new(path_str);
        if !path.exists() {
            return Err(format!("NalKey file not found: {}", path_str));
        }
        load_nalkey(path)
    } else {
        Err("invalid selection. Please enter 1 or 2.".to_string())
    }
}

// file type detection
#[cfg(unix)]
fn detect_file_type(path: &Path) -> Option<String> {
    use std::process::Command;
    let output = Command::new("file")
    .args(&["-b", path.to_str()?])
    .output()
    .ok()?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout);
        let s = s.trim();
        if !s.is_empty() && !s.starts_with("data") {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(not(unix))]
fn detect_file_type(_path: &Path) -> Option<String> {
    None
}

// interactive interface
fn run_interactive() {
    println!("NalTool - Made by Kacefier");
    println!("GitHub: github.com/Kacefier/NalTool\nEmail: kacefier@zohomail.com");
    println!("Version {}", VERSION);

    loop {
        println!();
        println!("[1] Encrypt text");
        println!("[2] Decrypt text");
        println!("[3] Encrypt file");
        println!("[4] Decrypt file");
        println!("[5] Generate NalKey file");
        println!("[6] Exit");
        println!();

        print!("Select operation (1-6): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        if io::stdin().read_line(&mut choice).is_err() {
            break;
        }
        let choice = choice.trim();

        match choice {
            "1" => {
                print!("Enter text to encrypt: ");
                io::stdout().flush().unwrap();
                let mut text = String::new();
                if io::stdin().read_line(&mut text).is_err() {
                    eprintln!("Error reading text");
                    continue;
                }
                let text = text.trim_end();
                if text.is_empty() {
                    eprintln!("Error: text cannot be empty");
                    continue;
                }

                println!("\nGetting encryption key...");
                let password = match get_key_from_args(None, None, "Enter encryption key: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                };

                match encrypt_text(text, &password) {
                    Ok(result) => {
                        println!("\nEncryption result (length: {}):", result.len());
                        println!("{}", result);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }

            "2" => {
                print!("Enter ciphertext to decrypt: ");
                io::stdout().flush().unwrap();
                let mut encrypted = String::new();
                if io::stdin().read_line(&mut encrypted).is_err() {
                    eprintln!("Error reading ciphertext");
                    continue;
                }
                let encrypted = encrypted.trim_end();
                if encrypted.is_empty() {
                    eprintln!("Error: ciphertext cannot be empty");
                    continue;
                }

                println!("\nGetting decryption key...");
                let password = match get_key_from_args(None, None, "Enter decryption key: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                };

                match decrypt_text(encrypted, &password) {
                    Ok(result) => {
                        println!("\nDecryption result (length: {}):", result.len());
                        println!("{}", result);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }

            "3" => {
                print!("Enter file path: ");
                io::stdout().flush().unwrap();
                let mut filepath = String::new();
                if io::stdin().read_line(&mut filepath).is_err() {
                    eprintln!("Error reading file path");
                    continue;
                }
                let filepath = filepath.trim();
                let input_path = Path::new(filepath);

                if !input_path.exists() {
                    eprintln!("Error: file not found: {}", filepath);
                    continue;
                }

                let file_size = match fs::metadata(input_path) {
                    Ok(m) => m.len(),
                    Err(e) => {
                        eprintln!("Error: cannot read file metadata: {}", e);
                        continue;
                    }
                };

                print!("Compress file? (y/n): ");
                io::stdout().flush().unwrap();
                let mut compress_input = String::new();
                if io::stdin().read_line(&mut compress_input).is_err() {
                    eprintln!("Error reading input");
                    continue;
                }
                let compress = compress_input.trim().to_lowercase() == "y";

                println!("\nGetting encryption key...");
                let password = match get_key_from_args(None, None, "Enter encryption key: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                };

                let output_path = PathBuf::from(format!("{}.nalfile", input_path.to_string_lossy()));
                println!("Encrypting file... (size: {} bytes)", format_with_commas(file_size));
                let start = Instant::now();

                match encrypt_file(input_path, &output_path, &password, compress, 6) {
                    Ok(_) => {
                        let elapsed = start.elapsed();
                        let output_size = match fs::metadata(&output_path) {
                            Ok(m) => m.len(),
                            Err(_) => 0,
                        };
                        println!("Encryption successful: {}", output_path.display());
                        println!("Original size: {} bytes", format_with_commas(file_size));
                        println!("Encrypted size: {} bytes", format_with_commas(output_size));
                        if compress && output_size < file_size {
                            let ratio = 100.0 - (output_size as f64 / file_size as f64 * 100.0);
                            println!("Compression ratio: {:.1}% smaller", ratio);
                        }
                        println!("Time elapsed: {:.2} seconds", elapsed.as_secs_f64());
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        let _ = fs::remove_file(&output_path);
                    }
                }
            }

            "4" => {
                print!("Enter file path: ");
                io::stdout().flush().unwrap();
                let mut filepath = String::new();
                if io::stdin().read_line(&mut filepath).is_err() {
                    eprintln!("Error reading file path");
                    continue;
                }
                let filepath = filepath.trim();
                let input_path = Path::new(filepath);

                if !input_path.exists() {
                    eprintln!("Error: file not found: {}", filepath);
                    continue;
                }

                println!("\nGetting decryption key...");
                let password = match get_key_from_args(None, None, "Enter decryption key: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                };

                let mut output_path = if filepath.ends_with(".nalfile") {
                    Path::new(&filepath[..filepath.len() - 8]).to_path_buf()
                } else {
                    input_path.with_extension("dec")
                };

                if output_path.exists() {
                    let stem = output_path.file_stem().unwrap().to_string_lossy();
                    let ext = output_path.extension().unwrap_or_default();
                    output_path = PathBuf::from(format!("{}_{}.{}", stem, "decrypted", ext.to_string_lossy()));
                }

                let file_size = match fs::metadata(input_path) {
                    Ok(m) => m.len(),
                    Err(e) => {
                        eprintln!("Error: cannot read file metadata: {}", e);
                        continue;
                    }
                };

                println!("Decrypting file... (size: {} bytes)", format_with_commas(file_size));
                let start = Instant::now();

                match decrypt_file(input_path, &output_path, &password) {
                    Ok(_) => {
                        let elapsed = start.elapsed();
                        let output_size = match fs::metadata(&output_path) {
                            Ok(m) => m.len(),
                            Err(_) => 0,
                        };
                        println!("Decryption successful: {}", output_path.display());
                        println!("Recovered size: {} bytes", format_with_commas(output_size));
                        println!("Time elapsed: {:.2} seconds", elapsed.as_secs_f64());

                        if let Some(file_type) = detect_file_type(&output_path) {
                            println!("File type: {}", file_type);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        let _ = fs::remove_file(&output_path);
                    }
                }
            }

            "5" => {
                println!("\nGenerating NalKey file...");

                print!("Enter NalKey file path (e.g., /path/to/key.nalkey): ");
                io::stdout().flush().unwrap();
                let mut path_str = String::new();
                if io::stdin().read_line(&mut path_str).is_err() {
                    eprintln!("Error reading path");
                    continue;
                }
                let path_str = path_str.trim();
                if path_str.is_empty() {
                    eprintln!("Error: path cannot be empty");
                    continue;
                }

                let original_key = match get_password_with_asterisk("Enter key to store in NalKey: ") {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                };

                if original_key.is_empty() {
                    eprintln!("Error: key cannot be empty");
                    continue;
                }

                let path = Path::new(path_str);
                match generate_nalkey_at_path(&original_key, path) {
                    Ok(_) => println!("NalKey generated successfully: {}", path.display()),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }

            "6" => {
                println!("Goodbye...");
                break;
            }

            _ => eprintln!("Invalid option, please try again"),
        }
    }
}

// main functions
fn main() {
    let cli = Cli::parse();

    if cli.version {
        println!("NalTool version {} - Made by Kacefier", VERSION);
        return;
    }

    if cli.help {
        println!("NalTool - Made by Kacefier");
        println!("GitHub: github.com/Kacefier/NalTool\nEmail: kacefier@zohomail.com");
        println!("Version {}", VERSION);
        println!();
        println!("Usage:");
        println!("  naltool [OPTIONS]");
        println!();
        println!("Options:");
        println!("  -v, --version                  Show version information");
        println!("  -i, --interface                Enter interactive interface");
        println!("  -h, --help                     Show this help message");
        println!("  -e, --encrypt <FILE|TEXT>      Encrypt file or text");
        println!("  -d, --decrypt <FILE|TEXT>      Decrypt file or text");
        println!("      --text                     Treat input as text (use with -e/-d)");
        println!("  -k, --key <KEY>                Encryption key (no spaces allowed)");
        println!("  -n, --nalkey <PATH>            Path to NalKey file");
        println!("      --new                      Generate new NalKey file (interactive)");
        println!("  -c, --compress                 Enable compression");
        println!("  -l, --level <LEVEL>            Compression level (1-9, default: 3)");
        println!();
        println!("Examples:");
        println!("  naltool -i                             Enter interactive interface");
        println!("  naltool -e file.txt -k \"key\"           Encrypt file.txt with key");
        println!("  naltool -d file.nalfile -k \"key\"       Decrypt file with key");
        println!("  naltool -e file.txt -n /path/to/key.nalkey       Encrypt using NalKey");
        println!("  naltool -d file.nalfile -n /path/to/key.nalkey   Decrypt using NalKey");
        println!("  naltool -e \"hello\" --text -k \"key\"               Encrypt text");
        println!("  naltool -d \"ciphertext\" --text -k \"key\"          Decrypt text");
        println!("  naltool -e file.txt -c -l 9            Encrypt with max compression");
        println!("  naltool --new                          Generate NalKey file");
        println!();
        println!("NOTE: Keys via -k cannot contain spaces. Use NalKey or interactive input for keys with spaces.");
        return;
    }

    if cli.interface {
        run_interactive();
        return;
    }

    if cli.new {
        print!("Enter NalKey file path (e.g., /path/to/key.nalkey): ");
        io::stdout().flush().unwrap();
        let mut path_str = String::new();
        if io::stdin().read_line(&mut path_str).is_err() {
            eprintln!("Error reading path");
            return;
        }
        let path_str = path_str.trim();
        if path_str.is_empty() {
            eprintln!("Error: path cannot be empty");
            return;
        }

        let password = match get_password_with_asterisk("Enter key to store in NalKey: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        };

        if password.is_empty() {
            eprintln!("Error: key cannot be empty");
            return;
        }

        let path = Path::new(path_str);
        match generate_nalkey_at_path(&password, path) {
            Ok(_) => {
                println!("NalKey generated: {}", path.display());
            }
            Err(e) => eprintln!("Error: {}", e),
        }
        return;
    }

    if let Some(input) = cli.encrypt {
        let key = match get_key_from_args(cli.key, cli.nalkey, "Enter encryption key: ") {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        };

        if cli.text {
            match encrypt_text(&input, &key) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("Error: {}", e),
            }
        } else {
            let input_path = Path::new(&input);
            if !input_path.exists() {
                eprintln!("Error: file not found: {}", input);
                return;
            }
            let output_path = PathBuf::from(format!("{}.nalfile", input));
            match encrypt_file(input_path, &output_path, &key, cli.compress, cli.compress_level) {
                Ok(_) => println!("Encrypted: {}", output_path.display()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        return;
    }

    if let Some(input) = cli.decrypt {
        let key = match get_key_from_args(cli.key, cli.nalkey, "Enter decryption key: ") {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        };

        if cli.text {
            match decrypt_text(&input, &key) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("Error: {}", e),
            }
        } else {
            let input_path = Path::new(&input);
            if !input_path.exists() {
                eprintln!("Error: file not found: {}", input);
                return;
            }

            let mut output_path = if input.ends_with(".nalfile") {
                Path::new(&input[..input.len() - 8]).to_path_buf()
            } else {
                input_path.with_extension("dec")
            };

            if output_path.exists() {
                let stem = output_path.file_stem().unwrap().to_string_lossy();
                let ext = output_path.extension().unwrap_or_default();
                output_path = PathBuf::from(format!("{}_{}.{}", stem, "decrypted", ext.to_string_lossy()));
            }

            match decrypt_file(input_path, &output_path, &key) {
                Ok(_) => println!("Decrypted: {}", output_path.display()),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        return;
    }

    println!("NalTool - Made by Kacefier");
    println!();
    println!("Try 'naltool --help' for more information.");
}

// Made by Kacefier
