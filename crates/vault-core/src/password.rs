//! Secure password generator and entropy scoring.
//!
//! Generator supports 8–128 characters and configurable character sets.
//! Entropy is estimated with a Shannon model plus common-pattern penalties
//! (lightweight stand-in aligned with zxcvbn-style scoring).

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{VaultError, VaultResult};

/// Minimum generated password length (product policy).
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum generated password length (product policy).
pub const MAX_PASSWORD_LEN: usize = 128;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
// Ambiguous characters often excluded for human readability.
const AMBIGUOUS: &[u8] = b"0O1lI|`";

/// Character-set configuration for the password generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// When true, removes characters that are easy to confuse (0/O, 1/l/I).
    pub exclude_ambiguous: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordPolicy {
    fn charset(&self) -> VaultResult<Vec<u8>> {
        if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&self.length) {
            return Err(VaultError::InvalidPasswordPolicy(format!(
                "length must be {MIN_PASSWORD_LEN}..={MAX_PASSWORD_LEN}"
            )));
        }
        let mut set = Vec::new();
        if self.lowercase {
            set.extend_from_slice(LOWER);
        }
        if self.uppercase {
            set.extend_from_slice(UPPER);
        }
        if self.digits {
            set.extend_from_slice(DIGITS);
        }
        if self.symbols {
            set.extend_from_slice(SYMBOLS);
        }
        if set.is_empty() {
            return Err(VaultError::InvalidPasswordPolicy(
                "at least one character class must be enabled".into(),
            ));
        }
        if self.exclude_ambiguous {
            set.retain(|c| !AMBIGUOUS.contains(c));
            if set.is_empty() {
                return Err(VaultError::InvalidPasswordPolicy(
                    "charset empty after excluding ambiguous characters".into(),
                ));
            }
        }
        Ok(set)
    }

    fn required_classes(&self) -> Vec<&'static [u8]> {
        let mut classes = Vec::new();
        if self.lowercase {
            classes.push(LOWER);
        }
        if self.uppercase {
            classes.push(UPPER);
        }
        if self.digits {
            classes.push(DIGITS);
        }
        if self.symbols {
            classes.push(SYMBOLS);
        }
        classes
    }
}

/// Generate a cryptographically random password conforming to `policy`.
///
/// Guarantees at least one character from each enabled class when length
/// is sufficient.
pub fn generate_password(policy: &PasswordPolicy) -> VaultResult<String> {
    let charset = policy.charset()?;
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::with_capacity(policy.length);

    // Ensure each enabled class is represented.
    for class in policy.required_classes() {
        let filtered: Vec<u8> = if policy.exclude_ambiguous {
            class
                .iter()
                .copied()
                .filter(|c| !AMBIGUOUS.contains(c))
                .collect()
        } else {
            class.to_vec()
        };
        if filtered.is_empty() {
            continue;
        }
        if bytes.len() < policy.length {
            bytes.push(*filtered.choose(&mut rng).unwrap());
        }
    }

    while bytes.len() < policy.length {
        bytes.push(*charset.choose(&mut rng).unwrap());
    }

    // Fisher–Yates shuffle so required-class chars are not position-biased.
    for i in (1..bytes.len()).rev() {
        let j = rng.gen_range(0..=i);
        bytes.swap(i, j);
    }

    String::from_utf8(bytes)
        .map_err(|e| VaultError::Crypto(format!("password utf8: {e}")))
}

/// Entropy / strength score similar in spirit to zxcvbn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntropyScore {
    /// Estimated entropy in bits.
    pub bits: f64,
    /// Score 0 (worst) – 4 (best).
    pub score: u8,
    /// Human-readable label.
    pub label: &'static str,
    /// Optional feedback for weak passwords.
    pub feedback: Vec<String>,
}

/// Estimate password entropy and strength.
pub fn score_password(password: &str) -> EntropyScore {
    let len = password.chars().count();
    let mut pool = 0.0_f64;
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }
    if has_lower {
        pool += 26.0;
    }
    if has_upper {
        pool += 26.0;
    }
    if has_digit {
        pool += 10.0;
    }
    if has_symbol {
        pool += 32.0;
    }
    if pool == 0.0 {
        pool = 1.0;
    }

    let mut bits = (len as f64) * pool.log2();

    // Pattern penalties (common sequences, repeats, dictionary-ish).
    let mut feedback = Vec::new();
    let lower = password.to_lowercase();
    if lower.chars().all(|c| c == lower.chars().next().unwrap_or('\0')) && len > 1 {
        bits *= 0.25;
        feedback.push("Avoid repeated single character.".into());
    }
    if is_sequential(&lower) {
        bits *= 0.4;
        feedback.push("Avoid sequential characters.".into());
    }
    for common in COMMON_PASSWORDS {
        if lower == *common {
            bits = bits.min(10.0);
            feedback.push("This is a commonly used password.".into());
            break;
        }
    }
    if len < MIN_PASSWORD_LEN {
        feedback.push(format!("Use at least {MIN_PASSWORD_LEN} characters."));
        bits = bits.min(20.0);
    }

    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 36.0 => 1,
        b if b < 60.0 => 2,
        b if b < 128.0 => 3,
        _ => 4,
    };
    let label = match score {
        0 => "very weak",
        1 => "weak",
        2 => "fair",
        3 => "strong",
        _ => "very strong",
    };

    EntropyScore {
        bits,
        score,
        label,
        feedback,
    }
}

fn is_sequential(s: &str) -> bool {
    let bytes: Vec<u8> = s.bytes().collect();
    if bytes.len() < 3 {
        return false;
    }
    let mut asc = 0;
    let mut desc = 0;
    for w in bytes.windows(2) {
        if w[1] == w[0].wrapping_add(1) {
            asc += 1;
        }
        if w[1] == w[0].wrapping_sub(1) {
            desc += 1;
        }
    }
    asc >= bytes.len().saturating_sub(1) || desc >= bytes.len().saturating_sub(1)
}

const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "monkey",
    "login",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_default_length_and_classes() {
        let p = generate_password(&PasswordPolicy::default()).unwrap();
        assert_eq!(p.len(), 20);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_respects_length_bounds() {
        let policy = PasswordPolicy {
            length: 8,
            ..PasswordPolicy::default()
        };
        let p = generate_password(&policy).unwrap();
        assert_eq!(p.len(), 8);

        let policy = PasswordPolicy {
            length: 128,
            ..PasswordPolicy::default()
        };
        let p = generate_password(&policy).unwrap();
        assert_eq!(p.len(), 128);
    }

    #[test]
    fn reject_too_short_or_long() {
        let policy = PasswordPolicy {
            length: 7,
            ..PasswordPolicy::default()
        };
        assert!(generate_password(&policy).is_err());
        let policy = PasswordPolicy {
            length: 129,
            ..PasswordPolicy::default()
        };
        assert!(generate_password(&policy).is_err());
    }

    #[test]
    fn reject_empty_charset() {
        let policy = PasswordPolicy {
            length: 16,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(generate_password(&policy).is_err());
    }

    #[test]
    fn two_generations_differ() {
        let policy = PasswordPolicy::default();
        let a = generate_password(&policy).unwrap();
        let b = generate_password(&policy).unwrap();
        // Extremely unlikely to collide at length 20.
        assert_ne!(a, b);
    }

    #[test]
    fn score_common_password_low() {
        let s = score_password("password");
        assert!(s.score <= 1);
        assert!(!s.feedback.is_empty());
    }

    #[test]
    fn score_strong_random_high() {
        let policy = PasswordPolicy {
            length: 32,
            ..PasswordPolicy::default()
        };
        let p = generate_password(&policy).unwrap();
        let s = score_password(&p);
        assert!(s.score >= 3, "score={} bits={}", s.score, s.bits);
    }

    #[test]
    fn sequential_penalized() {
        let s = score_password("abcdefgh");
        assert!(s.bits < 40.0);
    }

    #[test]
    fn exclude_ambiguous_works() {
        let policy = PasswordPolicy {
            length: 64,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        let p = generate_password(&policy).unwrap();
        for c in AMBIGUOUS {
            assert!(!p.as_bytes().contains(c), "found ambiguous {}", *c as char);
        }
    }
}
