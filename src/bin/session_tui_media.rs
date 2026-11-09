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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ImagePreview {
    /// Each terminal cell is the top and bottom pixel of a half-block glyph.
    pub rows: Vec<Vec<([u8; 3], [u8; 3])>>,
}

/// Stored as `"<width>:<base64 of top,bottom RGB per cell>"`, about a third
/// the size of the original `{"rows":[[[[r,g,b],[r,g,b]],…]]}` JSON (which
/// is still read) and much faster to parse.
impl Serialize for ImagePreview {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        let width = self.rows.first().map_or(0, Vec::len);
        let mut bytes = Vec::with_capacity(self.rows.len() * width * 6);
        for row in &self.rows {
            for (top, bottom) in row {
                bytes.extend_from_slice(top);
                bytes.extend_from_slice(bottom);
            }
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&format!("{width}:{encoded}"))
    }
}

impl<'de> Deserialize<'de> for ImagePreview {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::Engine as _;
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Stored {
            Compact(String),
            Legacy { rows: Vec<Vec<([u8; 3], [u8; 3])>> },
        }
        match Stored::deserialize(deserializer)? {
            Stored::Legacy { rows } => Ok(Self { rows }),
            Stored::Compact(text) => {
                let invalid = || serde::de::Error::custom("invalid image preview");
                let (width, data) = text.split_once(':').ok_or_else(invalid)?;
                let width: usize = width.parse().map_err(|_| invalid())?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .map_err(|_| invalid())?;
                if width == 0 {
                    return Ok(Self::default());
                }
                if bytes.len() % (width * 6) != 0 {
                    return Err(invalid());
                }
                let rows = bytes
                    .chunks(width * 6)
                    .map(|row| {
                        row.chunks(6)
                            .map(|c| ([c[0], c[1], c[2]], [c[3], c[4], c[5]]))
                            .collect()
                    })
                    .collect();
                Ok(Self { rows })
            }
        }
    }
}

/// Cache path of one attachment of a message. Index 0 keeps the original
/// single-attachment layout so existing caches stay valid.
pub fn attachment_blob_path(
    root: &std::path::Path,
    peer: &str,
    timestamp: u64,
    index: usize,
) -> std::path::PathBuf {
    let mut params = blake2b_simd::Params::new();
    params.hash_length(16);
    let mut input = peer.as_bytes().to_vec();
    input.extend_from_slice(&timestamp.to_le_bytes());
    if index > 0 {
        input.extend_from_slice(&(index as u64).to_le_bytes());
    }
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

/// Decode an image from someone else with bounded memory: at most 8192 px
/// per side and 192 MB of buffers (a 16 MP RGBA image needs 64 MB), instead
/// of the library default of 512 MB, so a crafted image can't stall us.
pub fn decode_image(data: &[u8]) -> Result<image::DynamicImage, String> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(192 * 1024 * 1024);
    let mut reader = image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| e.to_string())?;
    reader.limits(limits);
    reader.decode().map_err(|e| e.to_string())
}

pub fn image_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()
}

/// Inline thumbnail size in terminal cells (each cell shows two pixel rows).
pub const PREVIEW_MAX_WIDTH: u32 = 20;
pub const PREVIEW_MAX_ROWS: u32 = 6;

/// Shrink an older, larger stored preview to the current thumbnail size
/// (nearest-neighbour on the stored pixels; no need to decrypt the image).
pub fn shrink_preview(preview: ImagePreview) -> ImagePreview {
    let rows = preview.rows.len();
    let width = preview.rows.first().map_or(0, Vec::len);
    let max_rows = PREVIEW_MAX_ROWS as usize;
    let max_width = PREVIEW_MAX_WIDTH as usize;
    if rows <= max_rows && width <= max_width {
        return preview;
    }
    // Work on pixel rows (2 per cell) so the aspect ratio is kept.
    let pixel_rows: Vec<Vec<[u8; 3]>> = preview
        .rows
        .iter()
        .flat_map(|row| {
            [
                row.iter().map(|(top, _)| *top).collect::<Vec<_>>(),
                row.iter().map(|(_, bottom)| *bottom).collect::<Vec<_>>(),
            ]
        })
        .collect();
    let scale = (pixel_rows.len() as f64 / (max_rows * 2) as f64)
        .max(width as f64 / max_width as f64)
        .max(1.0);
    let new_width = ((width as f64 / scale).floor() as usize).max(1);
    let new_pixel_rows = ((pixel_rows.len() as f64 / scale).floor() as usize).max(1);
    let sample = |x: usize, y: usize| {
        let sy = ((y as f64 * scale) as usize).min(pixel_rows.len() - 1);
        let sx = ((x as f64 * scale) as usize).min(width - 1);
        pixel_rows[sy][sx]
    };
    let background = [10, 17, 23];
    let rows = (0..new_pixel_rows)
        .step_by(2)
        .map(|y| {
            (0..new_width)
                .map(|x| {
                    let bottom = if y + 1 < new_pixel_rows {
                        sample(x, y + 1)
                    } else {
                        background
                    };
                    (sample(x, y), bottom)
                })
                .collect()
        })
        .collect();
    ImagePreview { rows }
}

pub fn image_preview(data: &[u8]) -> Option<ImagePreview> {
    let image = decode_image(data).ok()?;
    let image = image
        .thumbnail(PREVIEW_MAX_WIDTH, PREVIEW_MAX_ROWS * 2)
        .to_rgb8();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_round_trip_compact_and_read_legacy() {
        let preview = ImagePreview {
            rows: vec![vec![([1, 2, 3], [4, 5, 6]), ([7, 8, 9], [10, 11, 12])]; 3],
        };
        let json = serde_json::to_string(&preview).unwrap();
        assert!(json.starts_with("\"2:"), "{json}");
        assert_eq!(
            serde_json::from_str::<ImagePreview>(&json).unwrap(),
            preview
        );
        let legacy = r#"{"rows":[[[[1,2,3],[4,5,6]],[[7,8,9],[10,11,12]]]]}"#;
        assert_eq!(
            serde_json::from_str::<ImagePreview>(legacy).unwrap().rows,
            preview.rows[..1]
        );
        let empty = serde_json::to_string(&ImagePreview::default()).unwrap();
        assert_eq!(
            serde_json::from_str::<ImagePreview>(&empty).unwrap(),
            ImagePreview::default()
        );
    }

    #[test]
    fn old_previews_shrink_to_thumbnail_size() {
        let old = ImagePreview {
            rows: vec![vec![([1, 2, 3], [4, 5, 6]); 28]; 12],
        };
        let small = shrink_preview(old);
        assert!(small.rows.len() <= PREVIEW_MAX_ROWS as usize);
        assert!(small.rows[0].len() <= PREVIEW_MAX_WIDTH as usize);
        // Downscaled pixels come from the source image.
        let (top, bottom) = small.rows[0][0];
        assert!([[1, 2, 3], [4, 5, 6]].contains(&top));
        assert!([[1, 2, 3], [4, 5, 6]].contains(&bottom));
        let tiny = ImagePreview {
            rows: vec![vec![([0; 3], [0; 3]); 5]; 3],
        };
        assert_eq!(shrink_preview(tiny.clone()), tiny);
    }
}
