//! Trust anchor source implementations: compiled-in IANA root anchor and file override.

use std::path::{Path, PathBuf};

use data_encoding::HEXUPPER_PERMISSIVE;
use styx_proto::domain::rdata::DsRdata;
use styx_proto::Name;

use crate::domain::error::TrustAnchorError;
use crate::domain::policy::{DigestType, DnssecAlgorithm};
use crate::domain::ports::TrustAnchorSource;
use crate::domain::trust_anchor::{TrustAnchor, TrustAnchors};

/// Built-in IANA root trust anchors (KSK-2017 tag 20326 and KSK-2024 tag 38696).
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

// 38696 (KSK-2024, active root KSK since Oct 2026) SHA-256 digest:
// 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
const ROOT_KSK_2024_DIGEST: [u8; 32] = [
    0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
    0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
];

fn root_anchor(key_tag: u16, digest: [u8; 32]) -> TrustAnchor {
    TrustAnchor::new(
        Name::root(),
        DsRdata::new(
            key_tag,
            DnssecAlgorithm::RSASHA256.value(),
            DigestType::SHA256.value(),
            digest.to_vec(),
        ),
    )
}

impl TrustAnchorSource for PinnedRootAnchor {
    fn anchors(&self) -> TrustAnchors {
        tracing::info!(
            key_tags = ?[20326_u16, 38696_u16],
            algorithm = DnssecAlgorithm::RSASHA256.value(),
            "using pinned IANA root anchors"
        );
        TrustAnchors::new(root_anchor(20326, ROOT_KSK_2017_DIGEST))
            .with(root_anchor(38696, ROOT_KSK_2024_DIGEST))
    }
}

/// Trust anchors read from a local file (configured in TOML), in the DS presentation
/// form `dig DS` prints: `<owner> [<ttl>] [IN] DS <key tag> <algorithm> <digest type>
/// <digest>`, the digest possibly split across several whitespace-separated chunks.
#[derive(Debug, Clone)]
pub struct FileTrustAnchor {
    path: PathBuf,
    anchors: TrustAnchors,
}

impl FileTrustAnchor {
    /// Loads trust anchors from a local file asynchronously.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError`] if reading fails, a line is malformed, or the file
    /// holds no anchor.
    pub async fn load_from_path(path: impl AsRef<Path>) -> Result<Self, TrustAnchorError> {
        let path_buf = path.as_ref().to_path_buf();
        let content = tokio::fs::read_to_string(&path_buf).await?;
        Self::from_str_and_path(&content, path_buf)
    }

    /// Parses trust anchors from raw text content. Every non-blank, non-comment line must
    /// be a DS-form anchor: a line that is not is an error naming it, never skipped, so a
    /// typo in a rollover line cannot leave a partial anchor set.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError::Malformed`] for the first bad line and
    /// [`TrustAnchorError::Empty`] when no line holds an anchor.
    pub fn from_str_and_path(content: &str, path: PathBuf) -> Result<Self, TrustAnchorError> {
        let mut anchors = Vec::new();
        for (index, line) in content.lines().enumerate() {
            let line_number = index.saturating_add(1);
            let text = line.split(';').next().unwrap_or_default().trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let anchor = parse_anchor_line(text).map_err(|reason| TrustAnchorError::Malformed {
                line: line_number,
                reason,
            })?;
            anchors.push(anchor);
        }
        let anchors = TrustAnchors::from_vec(anchors)?;
        tracing::warn!(
            path = %path.display(),
            count = anchors.as_slice().len(),
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

impl TrustAnchorSource for FileTrustAnchor {
    fn anchors(&self) -> TrustAnchors {
        self.anchors.clone()
    }
}

/// The digest length each known DS digest type produces (RFC 4509, RFC 6605).
const fn digest_length(digest_type: DigestType) -> Option<usize> {
    match digest_type {
        DigestType::SHA1 => Some(20),
        DigestType::SHA256 => Some(32),
        DigestType::SHA384 => Some(48),
        _ => None,
    }
}

fn parse_anchor_line(text: &str) -> Result<TrustAnchor, String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let ds_index = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("DS"))
        .ok_or_else(|| "expected a DS record; DNSKEY-form anchors are not supported".to_owned())?;
    let (head, rest) = tokens.split_at(ds_index);
    let (owner_text, between) = head
        .split_first()
        .ok_or_else(|| "the owner name must come before DS".to_owned())?;
    if !between
        .iter()
        .all(|token| token.eq_ignore_ascii_case("IN") || token.parse::<u32>().is_ok())
    {
        return Err("only a TTL and the class IN may sit between the owner and DS".to_owned());
    }
    let owner =
        Name::from_ascii(owner_text).map_err(|error| format!("invalid owner name: {error}"))?;
    let fields = rest.get(1..).unwrap_or_default();
    let [key_tag, algorithm, digest_type, digest_chunks @ ..] = fields else {
        return Err("expected a key tag, an algorithm, a digest type and a digest".to_owned());
    };
    let key_tag: u16 = key_tag
        .parse()
        .map_err(|_| format!("invalid key tag {key_tag:?}"))?;
    let algorithm: u8 = algorithm
        .parse()
        .map_err(|_| format!("invalid algorithm {algorithm:?}"))?;
    let digest_type: u8 = digest_type
        .parse()
        .map_err(|_| format!("invalid digest type {digest_type:?}"))?;
    let digest = decode_digest(digest_chunks, DigestType::new(digest_type))?;
    Ok(TrustAnchor::new(
        owner,
        DsRdata::new(key_tag, algorithm, digest_type, digest),
    ))
}

fn decode_digest(chunks: &[&str], digest_type: DigestType) -> Result<Vec<u8>, String> {
    if chunks.is_empty() {
        return Err("missing digest".to_owned());
    }
    let hex = chunks.concat();
    let digest = HEXUPPER_PERMISSIVE
        .decode(hex.as_bytes())
        .map_err(|error| format!("digest is not hexadecimal: {error}"))?;
    match digest_length(digest_type) {
        Some(expected) if expected != digest.len() => Err(format!(
            "a digest of type {digest_type} is {expected} octets, got {}",
            digest.len()
        )),
        _ => Ok(digest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_2024: &str = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

    fn parse(content: &str) -> Result<FileTrustAnchor, TrustAnchorError> {
        FileTrustAnchor::from_str_and_path(content, PathBuf::from("anchors"))
    }

    #[test]
    fn a_digest_split_into_chunks_is_joined_and_matches_the_pinned_anchor() {
        let (left, right) = ROOT_2024.split_at(56);
        let file = parse(&format!(". 172800 IN DS 38696 8 2 {left} {right}\n")).unwrap();
        let anchors = file.anchors();
        let [anchor] = anchors.as_slice() else {
            panic!("one anchor expected");
        };
        assert_eq!(anchor.digest(), ROOT_KSK_2024_DIGEST.as_slice());
        assert_eq!(anchor.key_tag(), 38696);
        assert!(anchor.owner().is_root());
    }

    #[test]
    fn comments_blank_lines_and_lowercase_hex_are_accepted() {
        let content = format!(
            "; root anchors\n# rollover\n\n. IN DS 38696 8 2 {} ; KSK-2024\n",
            ROOT_2024.to_lowercase()
        );
        assert_eq!(parse(&content).unwrap().anchors().as_slice().len(), 1);
    }

    #[test]
    fn a_bad_line_is_an_error_naming_it_never_skipped() {
        let content = format!(". IN DS 38696 8 2 {ROOT_2024}\n. IN DNSKEY 257 3 8 AwEAAa==\n");
        let error = parse(&content).unwrap_err();
        assert!(
            matches!(error, TrustAnchorError::Malformed { line: 2, .. }),
            "{error}"
        );
    }

    #[test]
    fn a_digest_of_the_wrong_length_for_its_type_is_refused() {
        let truncated = ROOT_2024.get(..56).unwrap();
        let error = parse(&format!(". IN DS 38696 8 2 {truncated}\n")).unwrap_err();
        assert!(
            matches!(error, TrustAnchorError::Malformed { line: 1, .. }),
            "{error}"
        );
    }

    #[test]
    fn the_owner_must_come_before_ds_and_only_a_ttl_or_class_between() {
        for line in [
            format!("DS 38696 8 2 {ROOT_2024}"),
            format!(". CH DS 38696 8 2 {ROOT_2024}"),
        ] {
            assert!(
                matches!(parse(&line), Err(TrustAnchorError::Malformed { .. })),
                "{line}"
            );
        }
    }

    #[test]
    fn a_file_with_no_anchor_is_empty() {
        assert!(matches!(
            parse("; nothing here\n"),
            Err(TrustAnchorError::Empty)
        ));
    }
}
