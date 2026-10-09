//! Digests over a collection (v0.1 section 3.1).
//!
//! Section 3.1 requires a report to declare its tree shape as an identifier
//! from a closed set, and the appendix fixes the v0.1 set as `flat`,
//! `rfc6962` and `RFC9162_SHA256`. Each name maps to its own root function
//! here and any other name maps to none, so a shape outside the set can never
//! be hashed as one inside it.
//!
//! - `rfc6962` and `RFC9162_SHA256`: the Merkle Tree Hash of RFC 6962
//!   section 2.1 (RFC 9162 section 2.1.1 keeps it), leaf `0x00 || d`, node
//!   `0x01 || left || right`, split at the largest power of two below n.
//! - `flat`: SHA-256 over the concatenated SHA-256 of each leaf, in order.
//!   This construction is not stated in the v0.1 text; it was fixed by
//!   recomputing the committed members' digests (the corpus defines a member
//!   of the set by its vector pair, open item O3).

use sha2::{Digest, Sha256};

/// The closed set of tree-shape identifiers v0.1 admits.
pub const SHAPES: [&str; 3] = ["flat", "rfc6962", "RFC9162_SHA256"];

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn mth(leaves: &[Vec<u8>]) -> [u8; 32] {
    match leaves.len() {
        0 => sha(&[]),
        1 => sha(&[&[0u8], &leaves[0]]),
        n => {
            let mut k = 1;
            while k * 2 < n {
                k *= 2;
            }
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            sha(&[&[1u8], &left, &right])
        }
    }
}

/// The hex root of `leaves` under `shape`, or `None` for a shape outside the set.
pub fn root(shape: &str, leaves: &[Vec<u8>]) -> Option<String> {
    let digest = match shape {
        "flat" => {
            let mut h = Sha256::new();
            for leaf in leaves {
                h.update(sha(&[leaf]));
            }
            let out: [u8; 32] = h.finalize().into();
            out
        }
        "rfc6962" | "RFC9162_SHA256" => mth(leaves),
        _ => return None,
    };
    Some(hex(&digest))
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex SHA-256 of some bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha(&[bytes]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6962_empty_and_single_leaf() {
        // RFC 6962 section 2.1: MTH({}) = SHA-256() and MTH({d}) = SHA-256(0x00 || d).
        assert_eq!(
            root("rfc6962", &[]).as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(root("rfc6962", &[b"".to_vec()]), Some(sha256_hex(&[0u8])));
    }

    #[test]
    fn rfc9162_name_is_the_rfc6962_tree() {
        let leaves: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i]).collect();
        assert_eq!(root("rfc6962", &leaves), root("RFC9162_SHA256", &leaves));
    }

    #[test]
    fn a_duplicated_last_leaf_changes_the_root() {
        let three: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let mut four = three.clone();
        four.push(b"c".to_vec());
        assert_ne!(root("rfc6962", &three), root("rfc6962", &four));
    }

    #[test]
    fn free_text_shapes_have_no_root() {
        assert_eq!(root("RFC 9162 SHA-256", &[]), None);
        assert_eq!(root("", &[]), None);
    }
}
