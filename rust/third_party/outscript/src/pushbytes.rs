//! Bitcoin script PUSHDATA encoding/decoding.

/// Encodes a byte slice as a Bitcoin script push operation, choosing the
/// appropriate opcode (direct push for <=75 bytes, OP_PUSHDATA1/2/4 for larger).
pub fn push_bytes(v: &[u8]) -> Vec<u8> {
    let n = v.len();
    if n <= 75 {
        let mut out = Vec::with_capacity(1 + n);
        out.push(n as u8);
        out.extend_from_slice(v);
        out
    } else if n <= 0xff {
        let mut out = Vec::with_capacity(2 + n);
        out.push(0x4c); // OP_PUSHDATA1
        out.push(n as u8);
        out.extend_from_slice(v);
        out
    } else if n <= 0xffff {
        let mut out = Vec::with_capacity(3 + n);
        out.push(0x4d); // OP_PUSHDATA2
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(v);
        out
    } else {
        let mut out = Vec::with_capacity(5 + n);
        out.push(0x4e); // OP_PUSHDATA4
        out.extend_from_slice(&(n as u32).to_le_bytes());
        out.extend_from_slice(v);
        out
    }
}

/// Decodes a Bitcoin script push operation at the start of `v`, returning the
/// pushed data and the total number of bytes consumed. Returns `None` on error.
pub fn parse_push_bytes(v: &[u8]) -> Option<(&[u8], usize)> {
    if v.is_empty() {
        return None;
    }
    let p = v[0];
    let rest = &v[1..];
    if p <= 75 {
        let n = p as usize;
        if rest.len() >= n {
            return Some((&rest[..n], n + 1));
        }
        return None;
    }
    match p {
        0x4c => {
            // OP_PUSHDATA1
            if rest.is_empty() {
                return None;
            }
            let n = rest[0] as usize;
            let rest = &rest[1..];
            if rest.len() >= n {
                Some((&rest[..n], n + 2))
            } else {
                None
            }
        }
        0x4d => {
            // OP_PUSHDATA2
            if rest.len() < 2 {
                return None;
            }
            let n = u16::from_le_bytes([rest[0], rest[1]]) as usize;
            let rest = &rest[2..];
            if rest.len() >= n {
                Some((&rest[..n], n + 3))
            } else {
                None
            }
        }
        0x4e => {
            // OP_PUSHDATA4
            if rest.len() < 4 {
                return None;
            }
            let n = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let rest = &rest[4..];
            if rest.len() >= n {
                Some((&rest[..n], n + 5))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_push() {
        let v = [1u8, 2, 3];
        let enc = push_bytes(&v);
        assert_eq!(enc, vec![3, 1, 2, 3]);
        let (data, n) = parse_push_bytes(&enc).unwrap();
        assert_eq!(data, &v);
        assert_eq!(n, 4);
    }

    #[test]
    fn pushdata1() {
        let v = vec![0xaau8; 100];
        let enc = push_bytes(&v);
        assert_eq!(enc[0], 0x4c);
        assert_eq!(enc[1], 100);
        let (data, n) = parse_push_bytes(&enc).unwrap();
        assert_eq!(data, &v[..]);
        assert_eq!(n, 102);
    }

    #[test]
    fn pushdata2() {
        let v = vec![0xbbu8; 300];
        let enc = push_bytes(&v);
        assert_eq!(enc[0], 0x4d);
        let (data, n) = parse_push_bytes(&enc).unwrap();
        assert_eq!(data, &v[..]);
        assert_eq!(n, 303);
    }

    #[test]
    fn truncated() {
        assert!(parse_push_bytes(&[5, 1, 2]).is_none());
        assert!(parse_push_bytes(&[]).is_none());
    }
}
