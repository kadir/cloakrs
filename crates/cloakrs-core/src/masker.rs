//! Masking strategies for detected PII.

use crate::{CloakError, EntityType, PiiEntity, Result};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How detected PII should be masked.
///
/// # Examples
///
/// ```
/// use cloakrs_core::MaskStrategy;
///
/// let strategy = MaskStrategy::PartialMask {
///     reveal_prefix: 1,
///     reveal_suffix: 4,
///     mask_char: '*',
/// };
/// assert!(matches!(strategy, MaskStrategy::PartialMask { .. }));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskStrategy {
    /// Replace with a typed placeholder such as `[EMAIL]` or `[SSN]`.
    #[default]
    Redact,
    /// Preserve selected prefix and suffix characters while masking the middle.
    PartialMask {
        /// Number of characters to reveal at the start.
        reveal_prefix: usize,
        /// Number of characters to reveal at the end.
        reveal_suffix: usize,
        /// Character used for masked positions.
        mask_char: char,
    },
    /// Deterministic SHA-256 hash.
    Hash {
        /// Optional salt.
        salt: Option<String>,
    },
    /// Replace with deterministic fake-but-safe data.
    Replace,
    /// AES-256-GCM encryption.
    Encrypt {
        /// Encryption key.
        key: String,
    },
    /// Replace every finding with this exact string.
    Custom(String),
}

impl MaskStrategy {
    /// Returns the replacement text for a finding.
    #[must_use]
    pub fn replacement(&self, finding: &PiiEntity) -> String {
        match self.try_replacement(finding) {
            Ok(replacement) => replacement,
            Err(_) => finding.entity_type.redaction_tag(),
        }
    }

    /// Returns the replacement text for a finding, propagating fallible strategies.
    pub fn try_replacement(&self, finding: &PiiEntity) -> Result<String> {
        match self {
            Self::Redact => Ok(finding.entity_type.redaction_tag()),
            Self::PartialMask {
                reveal_prefix,
                reveal_suffix,
                mask_char,
            } => Ok(partial_mask(
                finding,
                *reveal_prefix,
                *reveal_suffix,
                *mask_char,
            )),
            Self::Hash { salt } => {
                if finding.entity_type == EntityType::UserPath {
                    Ok(hash_user_path(&finding.text, salt.as_deref()))
                } else {
                    Ok(hash_mask(finding, salt.as_deref(), DEFAULT_HASH_LENGTH))
                }
            }
            Self::Replace => Ok(replace_mask(finding)),
            Self::Encrypt { key } => encrypt_mask(finding, key),
            Self::Custom(replacement) => Ok(replacement.clone()),
        }
    }
}

const DEFAULT_HASH_LENGTH: usize = 16;
const MIN_HASH_LENGTH: usize = 8;
const MAX_HASH_LENGTH: usize = 64;
const NONCE_LENGTH: usize = 12;

/// Applies a masking strategy to text using the supplied findings.
///
/// Findings are deduplicated and then processed in descending span order so
/// earlier byte offsets remain valid while the string is modified.
///
/// # Examples
///
/// ```
/// use cloakrs_core::{apply_mask, Confidence, EntityType, MaskStrategy, PiiEntity, Span};
///
/// let finding = PiiEntity {
///     entity_type: EntityType::Email,
///     span: Span::new(8, 24),
///     text: "user@example.com".to_string(),
///     confidence: Confidence::new(0.95).unwrap(),
///     recognizer_id: "email_regex_v1".to_string(),
/// };
///
/// let masked = apply_mask("Contact user@example.com", &[finding], &MaskStrategy::Redact).unwrap();
/// assert_eq!(masked, "Contact [EMAIL]");
/// ```
pub fn apply_mask(text: &str, findings: &[PiiEntity], strategy: &MaskStrategy) -> Result<String> {
    let mut findings = deduplicate(findings);
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.span.start));

    let mut result = text.to_string();
    for finding in findings {
        validate_span(text, &finding)?;
        result.replace_range(
            finding.span.start..finding.span.end,
            &strategy.try_replacement(&finding)?,
        );
    }
    Ok(result)
}

/// Decrypts a value produced by [`MaskStrategy::Encrypt`].
///
/// # Examples
///
/// ```
/// use cloakrs_core::{apply_mask, decrypt_masked_value, Confidence, EntityType, MaskStrategy, PiiEntity, Span};
///
/// let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// let finding = PiiEntity {
///     entity_type: EntityType::Email,
///     span: Span::new(0, 16),
///     text: "user@example.com".to_string(),
///     confidence: Confidence::new(0.95).unwrap(),
///     recognizer_id: "email_regex_v1".to_string(),
/// };
///
/// let encrypted = apply_mask("user@example.com", &[finding], &MaskStrategy::Encrypt { key: key.to_string() }).unwrap();
/// assert_eq!(decrypt_masked_value(&encrypted, key).unwrap(), "user@example.com");
/// ```
pub fn decrypt_masked_value(value: &str, key: &str) -> Result<String> {
    let Some(encoded) = value
        .strip_prefix("ENC[")
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(CloakError::EncryptionError(
            "encrypted value must use ENC[...] format".to_string(),
        ));
    };

    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|error| CloakError::EncryptionError(error.to_string()))?;
    if bytes.len() <= NONCE_LENGTH {
        return Err(CloakError::EncryptionError(
            "encrypted payload is too short".to_string(),
        ));
    }

    let key = parse_hex_key(key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| CloakError::EncryptionError(error.to_string()))?;
    let nonce = Nonce::from_slice(&bytes[..NONCE_LENGTH]);
    let plaintext = cipher
        .decrypt(nonce, &bytes[NONCE_LENGTH..])
        .map_err(|error| CloakError::EncryptionError(error.to_string()))?;

    String::from_utf8(plaintext).map_err(|error| CloakError::EncryptionError(error.to_string()))
}

/// Deduplicates overlapping findings.
#[must_use]
pub fn deduplicate(findings: &[PiiEntity]) -> Vec<PiiEntity> {
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|finding| (finding.span.start, std::cmp::Reverse(finding.span.end)));

    let mut keep: Vec<PiiEntity> = Vec::with_capacity(sorted.len());
    for finding in sorted {
        if let Some(last) = keep.last_mut() {
            if finding.span.overlaps(last.span) {
                let merged = merge_overlapping(last, &finding);
                *last = merged;
                continue;
            }
        }
        keep.push(finding);
    }

    keep
}

fn merge_overlapping(left: &PiiEntity, right: &PiiEntity) -> PiiEntity {
    if left.span.start == right.span.start && left.span.end == right.span.end {
        return if right.confidence > left.confidence {
            right.clone()
        } else {
            left.clone()
        };
    }

    if right.span.len() > left.span.len()
        || (right.span.len() == left.span.len() && right.confidence > left.confidence)
    {
        right.clone()
    } else {
        left.clone()
    }
}

fn validate_span(text: &str, finding: &PiiEntity) -> Result<()> {
    let start = finding.span.start;
    let end = finding.span.end;
    if start <= end
        && end <= text.len()
        && text.is_char_boundary(start)
        && text.is_char_boundary(end)
    {
        Ok(())
    } else {
        Err(CloakError::InvalidSpan {
            start,
            end,
            len: text.len(),
        })
    }
}

fn partial_mask(
    finding: &PiiEntity,
    reveal_prefix: usize,
    reveal_suffix: usize,
    mask_char: char,
) -> String {
    match finding.entity_type {
        EntityType::Email => mask_email(&finding.text, mask_char),
        EntityType::CreditCard => mask_preserving_separators(&finding.text, 0, 4, mask_char),
        EntityType::PhoneNumber => mask_phone(&finding.text, mask_char),
        EntityType::Ssn => mask_preserving_separators(&finding.text, 0, 4, mask_char),
        EntityType::Iban => mask_preserving_separators(&finding.text, 2, 4, mask_char),
        EntityType::IpAddress => mask_ip(&finding.text),
        EntityType::Hostname => mask_hostname(&finding.text, mask_char),
        EntityType::UserPath => mask_user_path(&finding.text, mask_char),
        EntityType::Bsn => mask_preserving_separators(&finding.text, 0, 3, mask_char),
        EntityType::Aadhaar => mask_preserving_separators(&finding.text, 0, 4, mask_char),
        EntityType::Jwt => mask_jwt(&finding.text),
        EntityType::ApiKey | EntityType::AwsAccessKey => {
            mask_generic(&finding.text, 4, 4, mask_char)
        }
        _ => mask_generic(&finding.text, reveal_prefix, reveal_suffix, mask_char),
    }
}

fn hash_mask(finding: &PiiEntity, salt: Option<&str>, length: usize) -> String {
    hash_value(&finding.text, salt, length)
}

fn hash_value(value: &str, salt: Option<&str>, length: usize) -> String {
    let length = length.clamp(MIN_HASH_LENGTH, MAX_HASH_LENGTH);
    let mut hasher = Sha256::new();
    if let Some(salt) = salt {
        hasher.update(salt.as_bytes());
    }
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let hex = to_hex(&digest);
    format!("HASH:{}", &hex[..length])
}

fn hash_user_path(path: &str, salt: Option<&str>) -> String {
    let Some((range, username)) = user_path_username_range(path) else {
        return hash_value(path, salt, DEFAULT_HASH_LENGTH);
    };
    replace_range_owned(
        path,
        range,
        &hash_value(username, salt, DEFAULT_HASH_LENGTH),
    )
}

fn replace_mask(finding: &PiiEntity) -> String {
    let seed = deterministic_seed(&finding.text);
    match finding.entity_type {
        EntityType::Email => format!("user{}@example.test", seed % 10_000),
        EntityType::PhoneNumber => format!("+1 555 010 {:04}", seed % 10_000),
        EntityType::CreditCard => fake_card(seed),
        EntityType::Ssn => format!(
            "9{:02}-{:02}-{:04}",
            seed % 100,
            (seed / 100) % 100,
            (seed / 10_000) % 10_000
        ),
        EntityType::Iban => fake_iban(&finding.text),
        EntityType::Bsn => format!("99999{:04}", seed % 10_000),
        EntityType::Aadhaar => format!("9999 9999 {:04}", seed % 10_000),
        EntityType::IpAddress => "192.0.2.1".to_string(),
        EntityType::Url => "https://example.test/redacted".to_string(),
        EntityType::Jwt => "eyJhbGciOiJIUzI1NiJ9.[REPLACED].signature".to_string(),
        EntityType::ApiKey => format!("test_key_{:016x}", seed),
        EntityType::AwsAccessKey => "AKIAIOSFODNN7EXAMPLE".to_string(),
        EntityType::CryptoAddress => "0x0000000000000000000000000000000000000000".to_string(),
        EntityType::MacAddress => "02:00:00:00:00:01".to_string(),
        EntityType::Hostname => "host.example.test".to_string(),
        EntityType::UserPath => "/home/user/redacted".to_string(),
        _ => finding
            .entity_type
            .redaction_tag()
            .replace('[', "[REPLACED_"),
    }
}

fn fake_card(seed: u64) -> String {
    const CARDS: &[&str] = &[
        "4111111111111111",
        "5555555555554444",
        "378282246310005",
        "6011111111111117",
    ];
    CARDS[(seed as usize) % CARDS.len()].to_string()
}

fn fake_iban(original: &str) -> String {
    match original.get(..2).map(str::to_ascii_uppercase).as_deref() {
        Some("DE") => "DE89 3704 0044 0532 0130 00".to_string(),
        Some("GB") => "GB29 NWBK 6016 1331 9268 19".to_string(),
        Some("FR") => "FR14 2004 1010 0505 0001 3M02 606".to_string(),
        _ => "NL91 ABNA 0417 1643 00".to_string(),
    }
}

fn encrypt_mask(finding: &PiiEntity, key: &str) -> Result<String> {
    let key = parse_hex_key(key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| CloakError::EncryptionError(error.to_string()))?;
    let nonce_bytes = derive_nonce(finding);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, finding.text.as_bytes())
        .map_err(|error| CloakError::EncryptionError(error.to_string()))?;

    let mut payload = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    Ok(format!("ENC[{}]", BASE64_STANDARD.encode(payload)))
}

fn parse_hex_key(key: &str) -> Result<[u8; 32]> {
    if key.len() != 64 {
        return Err(CloakError::EncryptionError(
            "encryption key must be 32 bytes encoded as 64 hex characters".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in key.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CloakError::EncryptionError(
            "encryption key must contain only hex characters".to_string(),
        )),
    }
}

fn derive_nonce(finding: &PiiEntity) -> [u8; NONCE_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(finding.entity_type.redaction_tag().as_bytes());
    hasher.update(finding.span.start.to_le_bytes());
    hasher.update(finding.span.end.to_le_bytes());
    hasher.update(finding.recognizer_id.as_bytes());
    hasher.update(finding.text.as_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; NONCE_LENGTH];
    nonce.copy_from_slice(&digest[..NONCE_LENGTH]);
    nonce
}

fn deterministic_seed(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn mask_email(email: &str, mask_char: char) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return mask_generic(email, 0, 0, mask_char);
    };

    if local.is_empty() {
        return format!("{mask_char}@{domain}");
    }

    let mut chars = local.chars();
    let Some(first) = chars.next() else {
        return format!("{mask_char}@{domain}");
    };
    let masked_count = chars.count();
    format!(
        "{first}{}@{domain}",
        mask_char.to_string().repeat(masked_count)
    )
}

fn mask_preserving_separators(
    value: &str,
    reveal_prefix: usize,
    reveal_suffix: usize,
    mask_char: char,
) -> String {
    let sensitive_count = value.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    let mut sensitive_index = 0usize;

    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                sensitive_index += 1;
                if sensitive_index <= reveal_prefix
                    || sensitive_index > sensitive_count.saturating_sub(reveal_suffix)
                {
                    c
                } else {
                    mask_char
                }
            } else {
                c
            }
        })
        .collect()
}

fn mask_phone(phone: &str, mask_char: char) -> String {
    let reveal_prefix = usize::from(phone.starts_with('+')) * 2;
    mask_preserving_separators(phone, reveal_prefix, 2, mask_char)
}

fn mask_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.*.*", parts[0], parts[1])
    } else {
        "*".repeat(ip.chars().count())
    }
}

fn mask_hostname(hostname: &str, mask_char: char) -> String {
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 {
        return mask_generic(hostname, 0, 0, mask_char);
    }

    let last_index = labels.len() - 1;
    labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            if index == last_index || is_preserved_hostname_label(label) {
                (*label).to_string()
            } else if index == 0 {
                mask_hostname_first_label(label, mask_char)
            } else {
                mask_preserving_label_separators(label, mask_char)
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn is_preserved_hostname_label(label: &str) -> bool {
    matches!(
        label.to_ascii_lowercase().as_str(),
        "internal" | "local" | "lan" | "corp" | "private" | "intranet"
    )
}

fn mask_hostname_first_label(label: &str, mask_char: char) -> String {
    if let Some((prefix, rest)) = label.split_once('-') {
        if !prefix.is_empty() && !rest.is_empty() {
            return format!(
                "{prefix}-{}",
                mask_preserving_label_separators(rest, mask_char)
            );
        }
    }
    mask_generic(label, 2.min(label.chars().count()), 0, mask_char)
}

fn mask_preserving_label_separators(label: &str, mask_char: char) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                mask_char
            } else {
                c
            }
        })
        .collect()
}

fn mask_user_path(path: &str, mask_char: char) -> String {
    let Some((range, username)) = user_path_username_range(path) else {
        return mask_generic(path, 0, 0, mask_char);
    };
    replace_range_owned(
        path,
        range,
        &mask_char.to_string().repeat(username.chars().count()),
    )
}

fn user_path_username_range(path: &str) -> Option<(std::ops::Range<usize>, &str)> {
    if let Some(rest) = path.strip_prefix("/home/") {
        return username_range_after_prefix(path, "/home/".len(), rest, '/');
    }
    if let Some(rest) = path.strip_prefix("/Users/") {
        return username_range_after_prefix(path, "/Users/".len(), rest, '/');
    }
    let lower = path.to_ascii_lowercase();
    if let Some(index) = lower.find(r"\users\") {
        let prefix_end = index + r"\Users\".len();
        return username_range_after_prefix(path, prefix_end, &path[prefix_end..], '\\');
    }
    if path == "/root" || path.starts_with("/root/") {
        return Some((1..5, &path[1..5]));
    }
    None
}

fn username_range_after_prefix<'a>(
    path: &'a str,
    prefix_end: usize,
    rest: &'a str,
    separator: char,
) -> Option<(std::ops::Range<usize>, &'a str)> {
    let username_len = rest.find(separator).unwrap_or(rest.len());
    (username_len > 0).then(|| {
        let start = prefix_end;
        let end = prefix_end + username_len;
        (start..end, &path[start..end])
    })
}

fn replace_range_owned(value: &str, range: std::ops::Range<usize>, replacement: &str) -> String {
    let mut result = value.to_string();
    result.replace_range(range, replacement);
    result
}

fn mask_jwt(jwt: &str) -> String {
    let prefix: String = jwt.chars().take(10).collect();
    format!("{prefix}[TRUNCATED]")
}

fn mask_generic(
    value: &str,
    reveal_prefix: usize,
    reveal_suffix: usize,
    mask_char: char,
) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    let prefix = reveal_prefix.min(len);
    let suffix = reveal_suffix.min(len.saturating_sub(prefix));
    let mask_len = len.saturating_sub(prefix + suffix);

    let mut result = String::with_capacity(value.len());
    result.extend(&chars[..prefix]);
    result.extend(std::iter::repeat(mask_char).take(mask_len));
    result.extend(&chars[len - suffix..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Span};

    fn finding(entity_type: EntityType, start: usize, end: usize, text: &str) -> PiiEntity {
        PiiEntity {
            entity_type,
            span: Span::new(start, end),
            text: text.to_string(),
            confidence: Confidence::new(0.9).unwrap(),
            recognizer_id: "test_v1".to_string(),
        }
    }

    #[test]
    fn test_apply_mask_redact_replaces_pii_with_tag() {
        let text = "Email user@example.com now";
        let findings = [finding(EntityType::Email, 6, 22, "user@example.com")];
        let masked = apply_mask(text, &findings, &MaskStrategy::Redact).unwrap();
        assert_eq!(masked, "Email [EMAIL] now");
    }

    #[test]
    fn test_apply_mask_uses_reverse_span_order() {
        let text = "a@b.co and c@d.co";
        let findings = [
            finding(EntityType::Email, 0, 6, "a@b.co"),
            finding(EntityType::Email, 11, 17, "c@d.co"),
        ];
        let masked = apply_mask(text, &findings, &MaskStrategy::Redact).unwrap();
        assert_eq!(masked, "[EMAIL] and [EMAIL]");
    }

    #[test]
    fn test_partial_mask_email_preserves_domain() {
        let item = finding(EntityType::Email, 0, 16, "john@example.com");
        let masked = MaskStrategy::PartialMask {
            reveal_prefix: 0,
            reveal_suffix: 0,
            mask_char: '*',
        }
        .replacement(&item);
        assert_eq!(masked, "j***@example.com");
    }

    #[test]
    fn test_partial_mask_credit_card_preserves_separators() {
        let item = finding(EntityType::CreditCard, 0, 19, "4111-1111-1111-1111");
        let masked = MaskStrategy::PartialMask {
            reveal_prefix: 0,
            reveal_suffix: 4,
            mask_char: '*',
        }
        .replacement(&item);
        assert_eq!(masked, "****-****-****-1111");
    }

    #[test]
    fn test_partial_mask_hostname_preserves_structure() {
        let item = finding(
            EntityType::Hostname,
            0,
            31,
            "db-prod-01.internal.company.com",
        );
        let masked = MaskStrategy::PartialMask {
            reveal_prefix: 0,
            reveal_suffix: 0,
            mask_char: '*',
        }
        .replacement(&item);
        assert_eq!(masked, "db-****-**.internal.*******.com");
    }

    #[test]
    fn test_partial_mask_user_path_masks_username_only() {
        let item = finding(EntityType::UserPath, 0, 24, "/home/kadir/projects/app");
        let masked = MaskStrategy::PartialMask {
            reveal_prefix: 0,
            reveal_suffix: 0,
            mask_char: '*',
        }
        .replacement(&item);
        assert_eq!(masked, "/home/*****/projects/app");
    }

    #[test]
    fn test_partial_mask_windows_user_path_masks_username_only() {
        let item = finding(EntityType::UserPath, 0, 25, r"C:\Users\john.doe\Desktop");
        let masked = MaskStrategy::PartialMask {
            reveal_prefix: 0,
            reveal_suffix: 0,
            mask_char: '*',
        }
        .replacement(&item);
        assert_eq!(masked, r"C:\Users\********\Desktop");
    }

    #[test]
    fn test_apply_mask_invalid_span_returns_error() {
        let text = "short";
        let findings = [finding(EntityType::Email, 0, 99, "short")];
        assert!(apply_mask(text, &findings, &MaskStrategy::Redact).is_err());
    }

    #[test]
    fn test_hash_mask_is_deterministic_without_salt() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let strategy = MaskStrategy::Hash { salt: None };
        assert_eq!(strategy.replacement(&item), strategy.replacement(&item));
    }

    #[test]
    fn test_hash_mask_uses_expected_prefix_and_default_length() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let replacement = MaskStrategy::Hash { salt: None }.replacement(&item);
        assert!(replacement.starts_with("HASH:"));
        assert_eq!(replacement.len(), "HASH:".len() + DEFAULT_HASH_LENGTH);
    }

    #[test]
    fn test_hash_mask_salt_changes_output() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let without_salt = MaskStrategy::Hash { salt: None }.replacement(&item);
        let with_salt = MaskStrategy::Hash {
            salt: Some("prod".to_string()),
        }
        .replacement(&item);
        assert_ne!(without_salt, with_salt);
    }

    #[test]
    fn test_hash_mask_user_path_hashes_username_only() {
        let item = finding(EntityType::UserPath, 0, 24, "/home/kadir/projects/app");
        let replacement = MaskStrategy::Hash { salt: None }.replacement(&item);
        assert!(replacement.starts_with("/home/HASH:"));
        assert!(replacement.ends_with("/projects/app"));
    }

    #[test]
    fn test_hash_mask_length_is_clamped_to_bounds() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        assert_eq!(
            hash_mask(&item, None, 2).len(),
            "HASH:".len() + MIN_HASH_LENGTH
        );
        assert_eq!(
            hash_mask(&item, None, 128).len(),
            "HASH:".len() + MAX_HASH_LENGTH
        );
    }

    #[test]
    fn test_replace_email_uses_example_test_domain() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let replacement = MaskStrategy::Replace.replacement(&item);
        assert!(replacement.ends_with("@example.test"));
    }

    #[test]
    fn test_replace_is_deterministic_for_same_input() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        assert_eq!(
            MaskStrategy::Replace.replacement(&item),
            MaskStrategy::Replace.replacement(&item)
        );
    }

    #[test]
    fn test_replace_credit_card_uses_luhn_valid_test_number() {
        let item = finding(EntityType::CreditCard, 0, 16, "4111111111111111");
        let replacement = MaskStrategy::Replace.replacement(&item);
        assert!(luhn_valid_digits(&replacement));
    }

    #[test]
    fn test_replace_ssn_uses_reserved_area_range() {
        let item = finding(EntityType::Ssn, 0, 11, "123-45-6789");
        let replacement = MaskStrategy::Replace.replacement(&item);
        assert!(replacement.starts_with('9'));
    }

    #[test]
    fn test_encrypt_mask_round_trips() {
        let key = test_key();
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let encrypted = MaskStrategy::Encrypt { key: key.clone() }
            .try_replacement(&item)
            .unwrap();
        assert!(encrypted.starts_with("ENC["));
        assert_eq!(
            decrypt_masked_value(&encrypted, &key).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn test_encrypt_mask_is_deterministic_for_same_finding() {
        let key = test_key();
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let strategy = MaskStrategy::Encrypt { key };
        assert_eq!(
            strategy.try_replacement(&item).unwrap(),
            strategy.try_replacement(&item).unwrap()
        );
    }

    #[test]
    fn test_encrypt_mask_invalid_key_returns_error() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        assert!(MaskStrategy::Encrypt {
            key: "short".to_string()
        }
        .try_replacement(&item)
        .is_err());
    }

    #[test]
    fn test_decrypt_masked_value_wrong_key_fails() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let encrypted = MaskStrategy::Encrypt { key: test_key() }
            .try_replacement(&item)
            .unwrap();
        assert!(decrypt_masked_value(
            &encrypted,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        .is_err());
    }

    #[test]
    fn test_decrypt_masked_value_tampered_ciphertext_fails() {
        let item = finding(EntityType::Email, 0, 16, "user@example.com");
        let encrypted = MaskStrategy::Encrypt { key: test_key() }
            .try_replacement(&item)
            .unwrap();
        let tampered = encrypted.replace("A", "B");
        assert!(decrypt_masked_value(&tampered, &test_key()).is_err());
    }

    fn test_key() -> String {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string()
    }

    fn luhn_valid_digits(value: &str) -> bool {
        let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
        let mut sum = 0u32;
        let mut double = false;
        for digit in digits.iter().rev() {
            let mut value = *digit;
            if double {
                value *= 2;
                if value > 9 {
                    value -= 9;
                }
            }
            sum += value;
            double = !double;
        }
        sum % 10 == 0
    }
}
