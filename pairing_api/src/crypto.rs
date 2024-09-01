use {
    base64::{prelude::BASE64_STANDARD, DecodeError, Engine},
    chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
        ChaCha20Poly1305,
        Nonce,
    },
    std::string::FromUtf8Error,
};

// https://specs.walletconnect.com/2.0/specs/clients/core/crypto/
// crypto-envelopes
const TYPE_0: u8 = 0;
const TYPE_1: u8 = 1;
const TYPE_INDEX: usize = 0;
const TYPE_LENGTH: usize = 1;
const INIT_VEC_LEN: usize = 12;
const PUB_KEY_LENGTH: usize = 32;
const SYM_KEY_LENGTH: usize = 32;

pub type InitVec = [u8; INIT_VEC_LEN];
pub type SymKey = [u8; SYM_KEY_LENGTH];
pub type PubKey = [u8; PUB_KEY_LENGTH];

/// Payload encoding, decoding, encryption and decryption errors.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("Payload is not base64 encoded")]
    Base64Decode(#[from] DecodeError),
    #[error("Payload decryption failure: {0}")]
    Decryption(String),
    #[error("Payload encryption failure: {0}")]
    Encryption(String),
    #[error("Invalid Initialization Vector length={0}")]
    InitVecLen(usize),
    #[error("Invalid symmetrical key length={0}")]
    SymKeyLen(usize),
    #[error("Payload does not fit initialization vector (index: {0}..{1})")]
    ParseInitVecLen(usize, usize),
    #[error("Payload does not fit sender public key (index: {0}..{1})")]
    ParseSenderPublicKeyLen(usize, usize),
    #[error("Payload is not a valid JSON encoding")]
    PayloadJson(#[from] FromUtf8Error),
    #[error("Unsupported envelope type={0}")]
    UnsupportedEnvelopeType(u8),
    #[error("Unexpected envelope type={0}, expected={1}")]
    UnexpectedEnvelopeType(u8, u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeType<'a> {
    Type0,
    Type1 { sender_public_key: &'a PubKey },
}

/// Non-owning convenient representation of the decoded payload blob.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EncodingParams<'a> {
    /// Encrypted payload.
    sealed: &'a [u8],
    /// Initialization Vector.
    init_vec: &'a InitVec,
    envelope_type: EnvelopeType<'a>,
}

impl<'a> EncodingParams<'a> {
    fn parse_decoded(data: &'a [u8]) -> Result<Self, PayloadError> {
        let envelope_type = data[0];
        match envelope_type {
            TYPE_0 => {
                let init_vec_start_index: usize = TYPE_INDEX + TYPE_LENGTH;
                let init_vec_end_index: usize = init_vec_start_index + INIT_VEC_LEN;
                let sealed_start_index: usize = init_vec_end_index;
                Ok(EncodingParams {
                    init_vec: data[init_vec_start_index..init_vec_end_index]
                        .try_into()
                        .map_err(|_| {
                            PayloadError::ParseInitVecLen(init_vec_start_index, init_vec_end_index)
                        })?,
                    sealed: &data[sealed_start_index..],
                    envelope_type: EnvelopeType::Type0,
                })
            }
            TYPE_1 => {
                let key_start_index: usize = TYPE_INDEX + TYPE_LENGTH;
                let key_end_index: usize = key_start_index + PUB_KEY_LENGTH;
                let init_vec_start_index: usize = key_end_index;
                let init_vec_end_index: usize = init_vec_start_index + INIT_VEC_LEN;
                let sealed_start_index: usize = init_vec_end_index;
                let init_vec = data[init_vec_start_index..init_vec_end_index]
                    .try_into()
                    .map_err(|_| {
                        PayloadError::ParseInitVecLen(init_vec_start_index, init_vec_end_index)
                    })?;

                Ok(EncodingParams {
                    envelope_type: EnvelopeType::Type1 {
                        sender_public_key: data[sealed_start_index..key_end_index]
                            .try_into()
                            .map_err(|_| {
                                PayloadError::ParseSenderPublicKeyLen(
                                    init_vec_start_index,
                                    init_vec_end_index,
                                )
                            })?,
                    },
                    init_vec,
                    sealed: &data[sealed_start_index..],
                })
            }
            _ => Err(PayloadError::UnsupportedEnvelopeType(envelope_type)),
        }
    }
}

/// Encrypts and encodes the plain-text payload.
///
/// TODO: RNG as an input
pub fn encrypt_and_encode<T>(
    envelope_type: EnvelopeType,
    msg: T,
    key: &SymKey,
) -> Result<String, PayloadError>
where
    T: AsRef<[u8]>,
{
    let payload = Payload {
        msg: msg.as_ref(),
        aad: &[],
    };
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let sealed = encrypt(&nonce, payload, key)?;
    Ok(encode(
        envelope_type,
        sealed.as_slice(),
        nonce
            .as_slice()
            .try_into()
            .map_err(|_| PayloadError::InitVecLen(nonce.len()))?,
    ))
}

/// Decodes and decrypts the Type0 envelope payload.
pub fn decode_and_decrypt_type0<T>(msg: T, key: &[u8]) -> Result<String, PayloadError>
where
    T: AsRef<[u8]>,
{
    let data = BASE64_STANDARD.decode(msg)?;
    let decoded = EncodingParams::parse_decoded(&data)?;
    if let EnvelopeType::Type1 { .. } = decoded.envelope_type {
        return Err(PayloadError::UnexpectedEnvelopeType(TYPE_1, TYPE_0));
    }

    let payload = Payload {
        msg: decoded.sealed,
        aad: &[],
    };
    let decrypted = decrypt(decoded.init_vec.into(), payload, key)?;

    Ok(String::from_utf8(decrypted)?)
}

fn encrypt(nonce: &Nonce, payload: Payload<'_, '_>, key: &SymKey) -> Result<Vec<u8>, PayloadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let sealed = cipher
        .encrypt(nonce, payload)
        .map_err(|e| PayloadError::Encryption(e.to_string()))?;

    Ok(sealed)
}

fn encode(envelope_type: EnvelopeType, sealed: &[u8], init_vec: &InitVec) -> String {
    match envelope_type {
        EnvelopeType::Type0 => {
            BASE64_STANDARD.encode([&[TYPE_0], init_vec.as_slice(), sealed].concat())
        }
        EnvelopeType::Type1 { sender_public_key } => BASE64_STANDARD
            .encode([&[TYPE_1], sender_public_key.as_slice(), init_vec, sealed].concat()),
    }
}

fn decrypt(nonce: &Nonce, payload: Payload<'_, '_>, key: &[u8]) -> Result<Vec<u8>, PayloadError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let unsealed = cipher
        .decrypt(nonce, payload)
        .map_err(|e| PayloadError::Decryption(e.to_string()))?;

    Ok(unsealed)
}
