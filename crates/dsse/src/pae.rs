//! The DSSE Pre-Authentication Encoding.

/// The fixed DSSE version prefix, ASCII `DSSEv1`.
const PREFIX: &[u8] = b"DSSEv1 ";

/// Returns the DSSE Pre-Authentication Encoding of `payload_type` and `payload`.
///
/// The encoding is specified in `protocol.md` of
/// <https://github.com/secure-systems-lab/dsse> as
///
/// ```text
/// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
/// SP             = ASCII space [0x20]
/// LEN(s)         = ASCII decimal encoding of the byte length of s, with no leading zeros
/// ```
///
/// `LEN` counts **bytes**, not characters. For a `payload_type` outside ASCII the
/// two differ, and a signature computed over a character count does not verify
/// against one computed over a byte count.
///
/// The encoding is injective: the length prefixes fix the boundary between type
/// and body, so no two distinct `(type, payload)` pairs share a pre-image and a
/// signature minted for one payload type never verifies as another.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    // str::len is the UTF-8 byte length, which is what LEN is specified over.
    // chars().count() is the same for ASCII and wrong for everything else.
    let type_len = payload_type.len();
    let mut out = Vec::with_capacity(PREFIX.len() + 22 + payload_type.len() + payload.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(type_len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}
