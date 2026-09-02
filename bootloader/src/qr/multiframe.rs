// Versioned, payload-bound multi-frame QR transport shared with KasSigner iOS.

use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 2] = *b"KQ";
pub const VERSION: u8 = 2;
pub const DIGEST_LEN: usize = 16;
pub const SESSION_LEN: usize = 8;
pub const HEADER_LEN: usize = 33;
pub const MAX_FRAGMENT_LEN: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidPayload,
    InvalidFrame,
    OutputTooSmall,
}

pub struct Frame<'a> {
    pub kind: u8,
    pub session: [u8; SESSION_LEN],
    pub payload_len: u16,
    pub digest: [u8; DIGEST_LEN],
    pub index: u8,
    pub total: u8,
    pub fragment: &'a [u8],
}

pub fn payload_kind(payload: &[u8]) -> u8 {
    if payload.starts_with(b"KSPT") {
        1
    } else if payload.len() == 79 && payload[0] == crate::qr::payload::PAYLOAD_V1_RAW {
        2
    } else {
        0
    }
}

pub fn payload_metadata(
    payload: &[u8],
) -> Result<(u8, [u8; SESSION_LEN], [u8; DIGEST_LEN]), FrameError> {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return Err(FrameError::InvalidPayload);
    }
    let hash = Sha256::digest(payload);
    let mut session = [0u8; SESSION_LEN];
    session.copy_from_slice(&hash[16..24]);
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&hash[..DIGEST_LEN]);
    Ok((payload_kind(payload), session, digest))
}

pub fn encode_frame(
    payload: &[u8],
    index: u8,
    total: u8,
    output: &mut [u8],
) -> Result<usize, FrameError> {
    if total < 2 || index >= total {
        return Err(FrameError::InvalidFrame);
    }
    let balanced = payload.len().div_ceil(total as usize);
    if balanced == 0 || balanced > MAX_FRAGMENT_LEN {
        return Err(FrameError::InvalidPayload);
    }
    let offset = index as usize * balanced;
    let fragment_len = payload.len().saturating_sub(offset).min(balanced);
    if fragment_len == 0 {
        return Err(FrameError::InvalidFrame);
    }
    let encoded_len = HEADER_LEN + fragment_len.max(20);
    if output.len() < encoded_len {
        return Err(FrameError::OutputTooSmall);
    }
    let (kind, session, digest) = payload_metadata(payload)?;
    output[..encoded_len].fill(0);
    output[..2].copy_from_slice(&MAGIC);
    output[2] = VERSION;
    output[3] = kind;
    output[4..12].copy_from_slice(&session);
    output[12..14].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    output[14..30].copy_from_slice(&digest);
    output[30] = index;
    output[31] = total;
    output[32] = fragment_len as u8;
    output[HEADER_LEN..HEADER_LEN + fragment_len]
        .copy_from_slice(&payload[offset..offset + fragment_len]);
    Ok(encoded_len)
}

pub fn decode_frame(data: &[u8]) -> Result<Frame<'_>, FrameError> {
    if data.len() < HEADER_LEN || data[..2] != MAGIC || data[2] != VERSION {
        return Err(FrameError::InvalidFrame);
    }
    let payload_len = u16::from_be_bytes([data[12], data[13]]);
    let index = data[30];
    let total = data[31];
    let fragment_len = data[32] as usize;
    if payload_len == 0
        || total < 2
        || index >= total
        || fragment_len == 0
        || fragment_len > MAX_FRAGMENT_LEN
        || data.len() < HEADER_LEN + fragment_len
    {
        return Err(FrameError::InvalidFrame);
    }
    let mut session = [0u8; SESSION_LEN];
    session.copy_from_slice(&data[4..12]);
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&data[14..30]);
    Ok(Frame {
        kind: data[3],
        session,
        payload_len,
        digest,
        index,
        total,
        fragment: &data[HEADER_LEN..HEADER_LEN + fragment_len],
    })
}

pub fn verify_payload(payload: &[u8], kind: u8, digest: &[u8; DIGEST_LEN]) -> bool {
    if payload_kind(payload) != kind {
        return false;
    }
    let hash = Sha256::digest(payload);
    hash[..DIGEST_LEN] == digest[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_share_payload_metadata() {
        let payload = [b"KSPT".as_slice(), &[0x5au8; 180]].concat();
        let mut first_bytes = [0u8; 160];
        let mut second_bytes = [0u8; 160];
        let first_len = encode_frame(&payload, 0, 2, &mut first_bytes).unwrap();
        let second_len = encode_frame(&payload, 1, 2, &mut second_bytes).unwrap();
        let first = decode_frame(&first_bytes[..first_len]).unwrap();
        let second = decode_frame(&second_bytes[..second_len]).unwrap();
        assert_eq!(first.session, second.session);
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.payload_len as usize, payload.len());
        let mut rebuilt = Vec::new();
        rebuilt.extend_from_slice(first.fragment);
        rebuilt.extend_from_slice(second.fragment);
        assert_eq!(rebuilt, payload);
        assert!(verify_payload(&rebuilt, first.kind, &first.digest));
    }

    #[test]
    fn rejects_invalid_headers_and_detects_tampering() {
        let payload = [b"KSPT".as_slice(), &[0x33u8; 180]].concat();
        let mut encoded = [0u8; 160];
        let len = encode_frame(&payload, 0, 2, &mut encoded).unwrap();
        encoded[2] = VERSION + 1;
        assert_eq!(
            decode_frame(&encoded[..len]).unwrap_err(),
            FrameError::InvalidFrame
        );
        let (_, _, digest) = payload_metadata(&payload).unwrap();
        let mut tampered = payload.clone();
        tampered[10] ^= 1;
        assert!(!verify_payload(&tampered, payload_kind(&payload), &digest));
    }
}
