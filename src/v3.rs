//! tink v3 frame skeleton + message fragmentation.
//!
//! Mirrors the C/Python ports and the tie reference implementation
//! (`tlib/std/tink_v3.tie`); KAT vectors are byte-exact across languages.
//!
//! Frame (16-byte fixed header, big-endian; design doc §3):
//! ```text
//! [magic 0x74 0x6B][ver=3][type][flags u16][stream_id u32][seq u32][len u16]
//! [ext region: ext_len u16 + TLV bytes]?   (flags.EXT)
//! [payload: len bytes]                     (flags.OFFSET: first 4 bytes = u32 BE offset)
//! [tail: CRC32C 4B | AEAD tag 16B | none]
//! ```
//! Implemented subset: CRC32C tail, EXT region, single frames up to 65535
//! bytes, message fragmentation (> 65531 bytes split into OFFSET+FIN fragments,
//! seq = fragment index) with transparent reassembly on decode. PROTECTED
//! frames are rejected (crypto layer out of scope).

pub const T_MESSAGE: u8 = 0x04;
pub const F_EXT: u16 = 1;
pub const F_PROTECTED: u16 = 2;
pub const F_CRC: u16 = 4;
pub const F_FIN: u16 = 8;
pub const F_OFFSET: u16 = 16;
pub const F_URGENT: u16 = 32;

/// Max fragment data (65535 - 4-byte offset prefix).
pub const CHUNK_MAX: usize = 65531;

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC_TAB: [u32; 256] = crc_table();

/// CRC32C (Castagnoli, reflected poly 0x82F63B78; init/xorout 0xFFFFFFFF).
///
/// Check vector: `crc32c(b"123456789") == 0xE3069283`.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
        c = (c >> 8) ^ CRC_TAB[((c ^ b as u32) & 0xFF) as usize];
    }
    c ^ 0xFFFF_FFFF
}

fn frame_one(payload: &[u8], flags: u16, seq: u32, ext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 2 + ext.len() + payload.len() + 4);
    out.push(0x74);
    out.push(0x6B);
    out.push(3);
    out.push(T_MESSAGE);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // stream_id
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    if flags & F_EXT != 0 {
        out.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        out.extend_from_slice(ext);
    }
    out.extend_from_slice(payload);
    let c = crc32c(&out);
    out.extend_from_slice(&c.to_be_bytes());
    out
}

/// Single frame without extension region (CRC|FIN; payload up to 65535).
pub fn frame_encode(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 65535, "payload too large for a single frame");
    frame_one(payload, F_CRC | F_FIN, 0, &[])
}

/// Single frame carrying an extension region (raw TLV bytes).
pub fn frame_encode_ext(payload: &[u8], ext: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 65535 && ext.len() <= 65535, "payload or ext too large");
    let flags = F_CRC | F_FIN | if ext.is_empty() { 0 } else { F_EXT };
    frame_one(payload, flags, 0, ext)
}

/// Message layer: single frame when `payload.len() <= 65531`, else OFFSET fragments.
pub fn msg_encode(payload: &[u8]) -> Vec<u8> {
    if payload.len() <= CHUNK_MAX {
        return frame_one(payload, F_CRC | F_FIN, 0, &[]);
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut idx = 0u32;
    while off < payload.len() {
        let end = (off + CHUNK_MAX).min(payload.len());
        let chunk = &payload[off..end];
        let mut flags = F_CRC | F_OFFSET;
        if end == payload.len() {
            flags |= F_FIN;
        }
        let mut body = Vec::with_capacity(4 + chunk.len());
        body.extend_from_slice(&(off as u32).to_be_bytes());
        body.extend_from_slice(chunk);
        out.extend_from_slice(&frame_one(&body, flags, idx, &[]));
        off = end;
        idx += 1;
    }
    out
}

/// One parsed frame: (flags, payload_offset, payload_len, next_pos).
fn frame_read(b: &[u8], pos: usize) -> Option<(u16, usize, usize, usize)> {
    if pos + 16 > b.len() {
        return None;
    }
    if b[pos] != 0x74 || b[pos + 1] != 0x6B || b[pos + 2] != 3 || b[pos + 3] != T_MESSAGE {
        return None;
    }
    let flags = u16::from_be_bytes([b[pos + 4], b[pos + 5]]);
    if flags & 0xFFC0 != 0 || flags & F_PROTECTED != 0 {
        return None;
    }
    let mut eoff = pos + 16;
    if flags & F_EXT != 0 {
        if pos + 18 > b.len() {
            return None;
        }
        let elen = u16::from_be_bytes([b[pos + 16], b[pos + 17]]) as usize;
        eoff = pos + 18 + elen;
        if eoff > b.len() {
            return None;
        }
    }
    let ln = u16::from_be_bytes([b[pos + 14], b[pos + 15]]) as usize;
    let tlen = if flags & F_CRC != 0 { 4 } else { 0 };
    if eoff + ln + tlen > b.len() {
        return None;
    }
    if tlen == 4 {
        let want = u32::from_be_bytes([b[eoff + ln], b[eoff + ln + 1], b[eoff + ln + 2], b[eoff + ln + 3]]);
        if want != crc32c(&b[pos..eoff + ln]) {
            return None;
        }
    }
    Some((flags, eoff, ln, eoff + ln + tlen))
}

/// Decode one logical message at `pos`, reassembling fragments.
/// Returns `(payload, next_pos)` or `None` on malformed frame / CRC mismatch.
pub fn msg_decode(b: &[u8], pos: usize) -> Option<(Vec<u8>, usize)> {
    let (flags, po, pl, nx) = frame_read(b, pos)?;
    if flags & F_OFFSET == 0 {
        return Some((b[po..po + pl].to_vec(), nx));
    }
    if pl < 4 || u32::from_be_bytes([b[po], b[po + 1], b[po + 2], b[po + 3]]) != 0 {
        return None;
    }
    let mut out = b[po + 4..po + pl].to_vec();
    let mut cur = nx;
    let mut fin = flags & F_FIN != 0;
    while !fin {
        let (fl2, po2, pl2, nx2) = frame_read(b, cur)?;
        if fl2 & F_OFFSET == 0 || pl2 < 4 {
            return None;
        }
        let off2 = u32::from_be_bytes([b[po2], b[po2 + 1], b[po2 + 2], b[po2 + 3]]) as usize;
        if off2 != out.len() {
            return None;
        }
        out.extend_from_slice(&b[po2 + 4..po2 + pl2]);
        fin = fl2 & F_FIN != 0;
        cur = nx2;
    }
    Some((out, cur))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect()
    }

    #[test]
    fn crc_kat() {
        assert_eq!(crc32c(b"123456789"), 0xE3069283);
        assert_eq!(crc32c(&pat(9)), 2452382926);
        assert_eq!(crc32c(&[0u8; 32]), 2324772522);
        assert_eq!(crc32c(&[0xFFu8; 32]), 1655221059);
        assert_eq!(crc32c(&(0..32u8).collect::<Vec<_>>()), 1188919630);
    }

    #[test]
    fn single_frames() {
        let f = msg_encode(&pat(13));
        assert_eq!(f.len(), 33);
        assert_eq!(
            hex(&f),
            "746b0304000c0000000000000000000d030a11181f262d343b424950571d47ab1e"
        );
        let f2 = msg_encode(&(0..32u8).collect::<Vec<_>>());
        assert_eq!(
            hex(&f2),
            "746b0304000c00000000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fee038132"
        );
        let f0 = msg_encode(b"");
        assert_eq!(hex(&f0), "746b0304000c00000000000000000000e7ccf215");
    }

    #[test]
    fn ext_frame() {
        let f = frame_encode_ext(b"x", &[0x00, 0x02, 0x00, 0x01, 0x05]);
        assert_eq!(hex(&f), "746b0304000d000000000000000000010005000200010578479e613c");
        let r = msg_decode(&f, 0).unwrap();
        assert_eq!(r.0, b"x");
        assert_eq!(r.1, f.len());
    }

    #[test]
    fn fragmented() {
        let p = pat(70000);
        let f = msg_encode(&p);
        assert_eq!(f.len(), 70048);
        assert_eq!(hex(&f[..16]), "746b030400140000000000000000ffff");
        assert_eq!(hex(&f[65551..65555]), "112dd201");
        assert_eq!(hex(&f[65555..65575]), "746b0304001c000000000000000111790000fffb");
        assert_eq!(hex(&f[f.len() - 4..]), "38fb521f");
        let r = msg_decode(&f, 0).unwrap();
        assert_eq!(r.0, p);
        assert_eq!(r.1, f.len());
        let mut bad = f.clone();
        bad[65600] ^= 0x01;
        assert!(msg_decode(&bad, 0).is_none());
    }

    #[test]
    fn boundaries() {
        let p = pat(65535);
        let f = frame_encode(&p);
        assert_eq!(f.len(), 65555);
        assert_eq!(hex(&f[..16]), "746b0304000c0000000000000000ffff");
        assert_eq!(hex(&f[f.len() - 4..]), "4995f11e");
        assert_eq!(msg_encode(&p[..65532]).len(), 65532 + 2 * 24);
        // v1 frames are rejected (generational upgrade)
        let v1: Vec<u8> = vec![0, 0, 0, 3, 0xAA, 0xBB, 0xCC, 0, 0, 0, 0];
        assert!(msg_decode(&v1, 0).is_none());
    }

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }
}
