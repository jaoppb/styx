//! Trust anchor source implementations: compiled-in IANA root anchor and file override.

use std::path::{Path, PathBuf};

use styx_proto::Name;

use crate::domain::error::TrustAnchorError;
use crate::domain::ports::TrustAnchorSource;
use crate::domain::trust_anchor::TrustAnchor;

/// Built-in IANA root trust anchor (KSK-2017, Key Tag 20326).
#[derive(Debug, Clone, Copy, Default)]
pub struct PinnedRootAnchor;

impl PinnedRootAnchor {
    /// Creates a new [`PinnedRootAnchor`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// 20326 (KSK-2017) SHA-256 digest: E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
const ROOT_KSK_2017_DIGEST: [u8; 32] = [
    0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
    0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
];

impl TrustAnchorSource for PinnedRootAnchor {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustAnchorError> {
        tracing::info!(
            key_tag = 20326,
            algorithm = 8,
            "using pinned IANA root anchor"
        );
        let root = Name::root();
        Ok(vec![TrustAnchor::new(
            root,
            20326,
            8,
            2,
            ROOT_KSK_2017_DIGEST.to_vec(),
        )])
    }
}

/// Trust anchor loader from a local file override (configured in TOML).
#[derive(Debug, Clone)]
pub struct FileTrustAnchor {
    path: PathBuf,
    anchors: Vec<TrustAnchor>,
}

impl FileTrustAnchor {
    /// Creates a new [`FileTrustAnchor`] with pre-parsed anchors.
    #[must_use]
    pub fn new(path: impl AsRef<Path>, anchors: Vec<TrustAnchor>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            anchors,
        }
    }

    /// Loads trust anchors from a local file asynchronously.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError`] if reading fails or no valid anchors are found.
    pub async fn load_from_path(path: impl AsRef<Path>) -> Result<Self, TrustAnchorError> {
        let path_buf = path.as_ref().to_path_buf();
        let content = tokio::fs::read_to_string(&path_buf)
            .await
            .map_err(|error| TrustAnchorError::Io(error.to_string()))?;
        Self::from_str_and_path(&content, path_buf)
    }

    /// Parses trust anchors from raw text content.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError::Empty`] if no valid anchors are found.
    pub fn from_str_and_path(content: &str, path: PathBuf) -> Result<Self, TrustAnchorError> {
        let mut anchors = Vec::new();
        for line in content.lines() {
            if let Some(anchor) = parse_anchor_line(line) {
                anchors.push(anchor);
            }
        }

        if anchors.is_empty() {
            return Err(TrustAnchorError::Empty);
        }

        tracing::warn!(
            path = %path.display(),
            count = anchors.len(),
            "loaded trust anchor override from file"
        );
        Ok(Self { path, anchors })
    }

    /// Returns the file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn parse_hex_byte(high: u8, low: u8) -> Option<u8> {
    let high_digit = char::from(high).to_digit(16)?;
    let low_digit = char::from(low).to_digit(16)?;
    let value = (high_digit << 4) | low_digit;
    u8::try_from(value).ok()
}

fn decode_hex_string(hex_text: &str) -> Option<Vec<u8>> {
    let bytes = hex_text.as_bytes();
    if (bytes.len() & 1) != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() >> 1);
    let mut index = 0;
    while index < bytes.len() {
        let high = *bytes.get(index)?;
        let low = *bytes.get(index.saturating_add(1))?;
        out.push(parse_hex_byte(high, low)?);
        index = index.saturating_add(2);
    }
    Some(out)
}

fn parse_anchor_line(line: &str) -> Option<TrustAnchor> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    // Allow either: `<owner> [ttl] [IN] DS <key_tag> <alg> <digest_type> <digest>`
    // or: `<owner> <key_tag> <alg> <digest_type> <digest>`
    let ds_index = parts
        .iter()
        .position(|&part| part.eq_ignore_ascii_case("DS"));
    let (owner_text, key_tag_text, algorithm_text, digest_type_text, digest_text) = match ds_index {
        Some(index) => {
            let owner = *parts.first()?;
            let key_tag = *parts.get(index.saturating_add(1))?;
            let algorithm = *parts.get(index.saturating_add(2))?;
            let digest_type = *parts.get(index.saturating_add(3))?;
            let digest = *parts.get(index.saturating_add(4))?;
            (owner, key_tag, algorithm, digest_type, digest)
        }
        None => {
            if parts.len() < 5 {
                return None;
            }
            let owner = *parts.first()?;
            let key_tag = *parts.get(1)?;
            let algorithm = *parts.get(2)?;
            let digest_type = *parts.get(3)?;
            let digest = *parts.get(4)?;
            (owner, key_tag, algorithm, digest_type, digest)
        }
    };

    let owner = Name::from_ascii(owner_text).ok()?;
    let key_tag: u16 = key_tag_text.parse().ok()?;
    let algorithm: u8 = algorithm_text.parse().ok()?;
    let digest_type: u8 = digest_type_text.parse().ok()?;
    let digest = decode_hex_string(digest_text)?;

    Some(TrustAnchor::new(
        owner,
        key_tag,
        algorithm,
        digest_type,
        digest,
    ))
}

impl TrustAnchorSource for FileTrustAnchor {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustAnchorError> {
        Ok(self.anchors.clone())
    }
}
