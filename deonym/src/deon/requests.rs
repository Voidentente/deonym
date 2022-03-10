use rand::rngs::OsRng;
use rsa::errors::Error;
use rsa::padding::PaddingScheme;
use rsa::pkcs8::ToPublicKey;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::Digest;

use crate::deon::error::DeonError;

const PUT_REQUEST_TAG: u8 = 0x00;
const POP_REQUEST_TAG: u8 = 0x01;

#[allow(clippy::large_enum_variant)]
pub enum ClientRequest {
    Put {
        public_key: Option<RsaPublicKey>,
        payload: Option<Vec<u8>>,
        surb: Option<Vec<u8>>,
    },
    Pop {
        public_key: RsaPublicKey,
        secret_key: Option<RsaPrivateKey>,
        wingman: Vec<u8>,
    },
}

impl ClientRequest {
    fn encrypt(pk: &RsaPublicKey, cleartext: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut rng = OsRng;
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        pk.encrypt(&mut rng, padding, &cleartext)
    }
    fn decrypt(sk: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        sk.decrypt(padding, ciphertext)
    }
    fn sign(sk: &RsaPrivateKey, digest_in: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = rsa::Hash::SHA2_256;
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(hash));
        let digest = sha2::Sha256::digest(digest_in).to_vec();
        sk.sign(padding, &digest)
    }
    fn verify(pk: &RsaPublicKey, digest_in: &[u8], sig: &[u8]) -> Result<(), Error> {
        let hash = rsa::Hash::SHA2_256;
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(hash));
        let digest = sha2::Sha256::digest(digest_in).to_vec();
        pk.verify(padding, &digest, sig)
    }
    /// Public key: Public key of target service,
    /// Payload: (Optional) Any data,
    /// SURB: (Optional) SURB of target client
    fn serialize_put(
        public_key: Option<RsaPublicKey>,
        payload: Option<Vec<u8>>,
        surb: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, DeonError> {
        let mut payload = match payload {
            None => Vec::<u8>::new(),
            Some(payload) => payload,
        };

        let mut surb = match surb {
            None => Vec::<u8>::new(),
            Some(surb) => surb,
        };

        let pem = match public_key {
            None => Vec::<u8>::new(),
            Some(public_key) => match public_key.to_public_key_pem() {
                Err(e) => {
                    return Err(DeonError::RsaPkcs8(format!(
                        "Failed to create PEM from public key: {}",
                        e
                    )))
                }
                Ok(pem) => {
                    // When we have a pem, we also want to encrypt our payload & surb
                    if !payload.is_empty() {
                        payload = match Self::encrypt(&public_key, payload) {
                            Err(e) => {
                                return Err(DeonError::RsaCrypto(format!(
                                    "Failed to encrypt payload: {}",
                                    e
                                )))
                            }
                            Ok(cyphertext) => cyphertext,
                        };
                    }
                    if !surb.is_empty() {
                        surb = match Self::encrypt(&public_key, surb) {
                            Err(e) => {
                                return Err(DeonError::RsaCrypto(format!(
                                    "Failed to encrypt SURB: {}",
                                    e
                                )))
                            }
                            Ok(cyphertext) => cyphertext,
                        };
                    }
                    pem.as_bytes().to_vec()
                }
            },
        };

        let surb_len_bytes = (surb.len() as u64).to_be_bytes();
        let payload_len_bytes = (payload.len() as u64).to_be_bytes();
        let pem_len_bytes = (pem.len() as u64).to_be_bytes();

        Ok(std::iter::once(PUT_REQUEST_TAG)
            .chain(pem_len_bytes)
            .chain(pem)
            .chain(payload_len_bytes)
            .chain(payload)
            .chain(surb_len_bytes)
            .chain(surb)
            .collect())
    }
    /// Public key: Public key of target service,
    /// Secret key: Secret key of target service for signing,
    /// Wingman: Nym address of wingman
    fn serialize_pop(
        public_key: RsaPublicKey,
        secret_key: Option<RsaPrivateKey>,
        wingman: Vec<u8>,
    ) -> Result<Vec<u8>, DeonError> {
        let secret_key = match secret_key {
            None => {
                return Err(DeonError::NoSecretKey(
                    "Cannot sign pop request without secret key".to_string(),
                ))
            }
            Some(secret_key) => secret_key,
        };

        let pem = match public_key.to_public_key_pem() {
            Err(e) => {
                return Err(DeonError::RsaPkcs8(format!(
                    "Failed to create PEM from public key: {}",
                    e
                )))
            }
            Ok(pem) => pem.as_bytes().to_vec(),
        };

        let pem_len_bytes = (pem.len() as u64).to_be_bytes();

        let mut vector: Vec<u8> = std::iter::once(POP_REQUEST_TAG)
            .chain(wingman)
            .chain(pem_len_bytes)
            .chain(pem)
            .collect();

        let mut sig = match Self::sign(&secret_key, &vector) {
            Err(e) => {
                return Err(DeonError::RsaCrypto(format!(
                    "Failed to sign vector: {}",
                    e
                )))
            }
            Ok(sig) => sig,
        };

        let sig_len_bytes = (sig.len() as u64).to_be_bytes();

        vector.append(&mut sig_len_bytes.to_vec());
        vector.append(&mut sig);

        Ok(vector)
    }
    /// Serialize the request for transport over network
    pub fn serialize(self) -> Result<Vec<u8>, DeonError> {
        match self {
            ClientRequest::Put {
                public_key,
                payload,
                surb,
            } => Ok(Self::serialize_put(public_key, payload, surb)?),

            ClientRequest::Pop {
                public_key,
                secret_key,
                wingman,
            } => Ok(Self::serialize_pop(public_key, secret_key, wingman)?),
        }
    }
    /// b: Binary data to deserialize,
    /// Secret key: (Optional) Secret key of target service for decryption
    fn deserialize_put(b: &[u8], secret_key: Option<&RsaPrivateKey>) -> Result<Self, DeonError> {
        if b.len() < 1 + 3 * std::mem::size_of::<u64>() {
            return Err(DeonError::Malformed(format!(
                "Expected at least {} bytes, got {}",
                1 + 3 * std::mem::size_of::<u64>(),
                b.len()
            )));
        }

        /* Extraction */
        let pem_len_bytes = u64::from_be_bytes(
            b[1..1 + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if pem_len_bytes > (b.len() - 1 - 3 * std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::Malformed(format!(
                "Expected at most {} bytes for PEM, got {}",
                b.len() - 1 - 3 * std::mem::size_of::<u64>(),
                pem_len_bytes
            )));
        }
        let pem_bound = 1 + std::mem::size_of::<u64>() + pem_len_bytes as usize;
        let pem = &b[1 + std::mem::size_of::<u64>()..pem_bound].to_vec();

        let payload_len_bytes = u64::from_be_bytes(
            b[pem_bound..pem_bound + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if payload_len_bytes > (b.len() - pem_bound - 2 * std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::Malformed(format!(
                "Expected at most {} bytes for payload, got {}",
                b.len() - pem_bound - 2 * std::mem::size_of::<u64>(),
                payload_len_bytes
            )));
        }
        let payload_bound = pem_bound + std::mem::size_of::<u64>() + payload_len_bytes as usize;
        let payload = &b[pem_bound + std::mem::size_of::<u64>()..payload_bound].to_vec();

        let surb_len_bytes = u64::from_be_bytes(
            b[payload_bound..payload_bound + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if surb_len_bytes > (b.len() - payload_bound - std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::Malformed(format!(
                "Expected at most {} bytes for SURB, got {}",
                b.len() - payload_bound - std::mem::size_of::<u64>(),
                surb_len_bytes
            )));
        }
        let surb_bound = payload_bound + std::mem::size_of::<u64>() + surb_len_bytes as usize;
        let surb = &b[payload_bound + std::mem::size_of::<u64>()..surb_bound].to_vec();

        /* Processing */
        // Payloads are None if they are empty
        let mut payload = match payload.is_empty() {
            true => None,
            false => Some(payload.to_owned()),
        };
        let mut surb = match surb.is_empty() {
            true => None,
            false => Some(surb.to_owned()),
        };

        let public_key = match pem.is_empty() {
            true => None,
            false => {
                match secret_key {
                    None => {
                        // Payloads are None if they are encrypted but we can't decrypt them
                        payload = None;
                        surb = None;
                    }
                    Some(sk) => {
                        match payload {
                            None => {}
                            Some(given_payload) => {
                                payload = match Self::decrypt(sk, &given_payload) {
                                    Err(e) => {
                                        return Err(DeonError::RsaCrypto(format!(
                                            "Failed to decrypt payload: {}",
                                            e
                                        )))
                                    }
                                    Ok(cleartext) => Some(cleartext),
                                };
                            }
                        }
                        match surb {
                            None => {}
                            Some(given_surb) => {
                                surb = match Self::decrypt(sk, &given_surb) {
                                    Err(e) => {
                                        return Err(DeonError::RsaCrypto(format!(
                                            "Failed to decrypt SURB: {}",
                                            e
                                        )))
                                    }
                                    Ok(cleartext) => Some(cleartext),
                                };
                            }
                        }
                    }
                }

                // Convert pem
                match String::from_utf8(pem.to_owned()) {
                    Err(e) => {
                        return Err(DeonError::Malformed(format!(
                            "Failed to create PEM string from bytes: {}",
                            e
                        )))
                    }
                    Ok(string) => {
                        match rsa::pkcs8::FromPublicKey::from_public_key_pem(string.as_str()) {
                            Err(e) => {
                                return Err(DeonError::RsaPkcs8(format!(
                                    "Failed to create public key from PEM: {}",
                                    e
                                )))
                            }
                            Ok(public_key) => Some(public_key),
                        }
                    }
                }
            }
        };

        Ok(ClientRequest::Put {
            public_key,
            payload,
            surb,
        })
    }
    /// b: Binary data to deserialize
    fn deserialize_pop(b: &[u8]) -> Result<Self, DeonError> {
        if b.len() < 97 + 2 * std::mem::size_of::<u64>() {
            return Err(DeonError::Malformed(format!(
                "Expected at least {} bytes, got {}",
                97 + 2 * std::mem::size_of::<u64>(),
                b.len()
            )));
        }

        /* Extraction */
        let wingman = &b[1..97];

        let pem_len_bytes = u64::from_be_bytes(
            b[97..97 + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if pem_len_bytes > (b.len() - 97 - 2 * std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::Malformed(format!(
                "Expected at most {} bytes for PEM, got {}",
                b.len() - 97 - 2 * std::mem::size_of::<u64>(),
                b.len()
            )));
        }
        let pem_bound = 97 + std::mem::size_of::<u64>() + pem_len_bytes as usize;
        let pem = &b[97 + std::mem::size_of::<u64>()..pem_bound];

        let sig_len_bytes = u64::from_be_bytes(
            b[pem_bound..pem_bound + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if sig_len_bytes > (b.len() - pem_bound - std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::Malformed(format!(
                "Expected at most {} bytes for signature, got {}",
                b.len() - pem_bound - std::mem::size_of::<u64>(),
                sig_len_bytes
            )));
        }
        let sig_bound = pem_bound + std::mem::size_of::<u64>() + sig_len_bytes as usize;
        let sig = &b[pem_bound + std::mem::size_of::<u64>()..sig_bound];

        /* Processing */
        let public_key = match String::from_utf8(pem.to_owned()) {
            Err(e) => {
                return Err(DeonError::Malformed(format!(
                    "Failed to create PEM string from bytes: {}",
                    e
                )))
            }
            Ok(string) => match rsa::pkcs8::FromPublicKey::from_public_key_pem(string.as_str()) {
                Err(e) => {
                    return Err(DeonError::RsaPkcs8(format!(
                        "Failed to create public key from PEM: {}",
                        e
                    )))
                }
                Ok(public_key) => public_key,
            },
        };

        let digest_in: Vec<u8> = std::iter::once(POP_REQUEST_TAG)
            .chain(wingman.to_vec())
            .chain(pem_len_bytes.to_be_bytes())
            .chain(pem.to_vec())
            .collect();

        match Self::verify(&public_key, &digest_in, sig) {
            Err(e) => Err(DeonError::RsaCrypto(format!(
                "Failed to verify pop request: {}",
                e
            ))),
            Ok(_) => Ok(ClientRequest::Pop {
                public_key,
                secret_key: None,
                wingman: wingman.to_vec(),
            }),
        }
    }
    /// Deserialize the request for use in program
    /// /// b: Binary data to deserialize,
    /// Secret key: (Optional) Secret key of target service for decryption
    pub fn deserialize(b: &[u8], sk: Option<&RsaPrivateKey>) -> Result<Self, DeonError> {
        if b.len() < std::mem::size_of::<u8>() {
            return Err(DeonError::Malformed(format!(
                "Expected at least {} bytes, got {}",
                std::mem::size_of::<u8>(),
                b.len()
            )));
        }

        match b[0] {
            PUT_REQUEST_TAG => Self::deserialize_put(b, sk),
            POP_REQUEST_TAG => Self::deserialize_pop(b),
            _ => Err(DeonError::Malformed(format!(
                "Expected tag {} or {}, got {}",
                PUT_REQUEST_TAG, POP_REQUEST_TAG, b[0]
            ))),
        }
    }
}
