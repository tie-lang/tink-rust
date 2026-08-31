//! tink —— data-flow node frame protocol (universal, language-agnostic).
//!
//! Frame = `[len u32 BE][payload][crc u32 BE]`; `crc` = CRC32-IEEE (0xEDB88320).
//! Mirrors `std/tink.tie` (tie standard library) and any-language nodes;
//! pure functions over byte slices, IO (stdin/stdout) left to the caller.
//!
//! ```
//! let f = tink::frame_encode(b"hi");
//! let (payload, next) = tink::frame_next(&f, 0).unwrap();
//! assert_eq!(payload, b"hi");
//! assert_eq!(next, f.len());
//! ```

/// CRC32-IEEE over a byte slice (bit-loop, no table; matches zlib.crc32).
///
/// Check vector: `crc32("123456789") == 0xCBF43926`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Encode a payload into a full frame: `[len u32 BE][payload][crc u32 BE]`.
pub fn frame_encode(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32(payload).to_be_bytes());
    out
}

/// Parse one frame at `pos` (verifies CRC). Returns `(payload, next_pos)`;
/// `None` on out-of-bounds or CRC mismatch.
pub fn frame_next(bytes: &[u8], pos: usize) -> Option<(Vec<u8>, usize)> {
    if bytes.len() < pos + 8 {
        return None;
    }
    let n = u32::from_be_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
    let end = pos + 8 + n;
    if bytes.len() < end {
        return None;
    }
    let payload = bytes[pos + 4..pos + 4 + n].to_vec();
    let want = u32::from_be_bytes(bytes[pos + 4 + n..end].try_into().ok()?);
    if crc32(&payload) != want {
        return None;
    }
    Some((payload, end))
}

/// Skip one frame at `pos` without copying or verifying (zero-copy).
/// Returns `next_pos`; `None` on out-of-bounds.
pub fn frame_skip(bytes: &[u8], pos: usize) -> Option<usize> {
    if bytes.len() < pos + 8 {
        return None;
    }
    let n = u32::from_be_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
    let end = pos + 8 + n;
    if bytes.len() < end {
        return None;
    }
    Some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn frame_roundtrip() {
        let p = [1u8, 2, 3];
        let f = frame_encode(&p);
        let (back, next) = frame_next(&f, 0).expect("frame");
        assert_eq!(next, f.len());
        assert_eq!(back, p);
    }

    #[test]
    fn empty_frame_roundtrip() {
        let f = frame_encode(&[]);
        let (back, next) = frame_next(&f, 0).expect("frame");
        assert_eq!(next, f.len());
        assert!(back.is_empty());
    }

    #[test]
    fn crc_tamper_rejected() {
        let mut f = frame_encode(&[1, 2, 3]);
        f[5] += 1; // payload[1] tampered
        assert!(frame_next(&f, 0).is_none());
    }

    #[test]
    fn frame_skip_matches_len() {
        let f = frame_encode(&[1, 2, 3]);
        assert_eq!(frame_skip(&f, 0), Some(f.len()));
    }

    #[test]
    fn out_of_bounds() {
        let f = frame_encode(&[1, 2, 3]);
        assert!(frame_next(&f, f.len()).is_none());
        assert_eq!(frame_skip(&f, f.len()), None);
    }
}
