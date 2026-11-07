use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2_0_10::{Digest, Sha256};

/// Encrypt attachments in the AES-CBC/HMAC format used by Session clients.
/// The pointer carries 64 bytes of key material and a SHA-256 digest of the
/// complete `IV || ciphertext || HMAC` blob.
pub fn encrypt_attachment(plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    if plaintext.is_empty() {
        return Err("attachment is empty".into());
    }
    let key = libsession::crypto::random::random(64);
    let iv = libsession::crypto::random::random(16);
    let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(&key[..32], &iv)
        .map_err(|e| e.to_string())?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut blob = Vec::with_capacity(16 + ciphertext.len() + 32);
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ciphertext);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|e| e.to_string())?;
    mac.update(&blob);
    blob.extend_from_slice(&mac.finalize().into_bytes());
    let digest = Sha256::digest(&blob).to_vec();
    Ok((blob, key, digest))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub file_name: String,
    pub content_type: String,
    pub url: String,
    pub key: Vec<u8>,
    pub digest: Vec<u8>,
    pub size: u32,
    pub deterministic: bool,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ImagePreview {
    /// Each terminal cell is the top and bottom pixel of a half-block glyph.
    pub rows: Vec<Vec<([u8; 3], [u8; 3])>>,
}

pub fn attachment_blob_path(
    root: &std::path::Path,
    peer: &str,
    timestamp: u64,
) -> std::path::PathBuf {
    let mut params = blake2b_simd::Params::new();
    params.hash_length(16);
    let mut input = peer.as_bytes().to_vec();
    input.extend_from_slice(&timestamp.to_le_bytes());
    root.join("attachments").join(format!(
        "{}.blob",
        hex::encode(params.hash(&input).as_bytes())
    ))
}

pub fn decrypt_attachment(
    ciphertext: &[u8],
    key: &[u8],
    digest: &[u8],
    deterministic: bool,
) -> Result<Vec<u8>, String> {
    if deterministic || key.len() == 32 {
        let key: &[u8; 32] = key
            .try_into()
            .map_err(|_| "invalid deterministic attachment key".to_string())?;
        return libsession::crypto::attachments::decrypt(ciphertext, key)
            .map_err(|e| e.to_string());
    }

    if key.len() != 64 || ciphertext.len() < 64 {
        return Err("invalid Session attachment key or ciphertext length".into());
    }
    if !digest.is_empty() {
        let actual = Sha256::digest(ciphertext);
        if actual.as_slice() != digest {
            return Err("attachment digest check failed".into());
        }
    }
    let mac_start = ciphertext.len() - 32;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|e| e.to_string())?;
    mac.update(&ciphertext[..mac_start]);
    mac.verify_slice(&ciphertext[mac_start..])
        .map_err(|_| "attachment MAC check failed".to_string())?;
    cbc::Decryptor::<Aes256>::new_from_slices(&key[..32], &ciphertext[..16])
        .map_err(|e| e.to_string())?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext[16..mac_start])
        .map_err(|_| "attachment decryption failed".to_string())
}

pub fn image_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()
}

pub fn image_preview(data: &[u8]) -> Option<ImagePreview> {
    let image = image::load_from_memory(data).ok()?;
    let image = image.thumbnail(28, 24).to_rgb8();
    let width = image.width() as usize;
    let height = image.height() as usize;
    let background = [10, 17, 23];
    let mut rows = Vec::with_capacity(height.div_ceil(2));
    for y in (0..height).step_by(2) {
        let mut row = Vec::with_capacity(width);
        for x in 0..width {
            let top = image.get_pixel(x as u32, y as u32).0;
            let bottom = if y + 1 < height {
                image.get_pixel(x as u32, (y + 1) as u32).0
            } else {
                background
            };
            row.push(([top[0], top[1], top[2]], [bottom[0], bottom[1], bottom[2]]));
        }
        rows.push(row);
    }
    Some(ImagePreview { rows })
}
