use rand::rngs::OsRng;
use rsa::errors::Error;
use rsa::padding::PaddingScheme;
use rsa::pkcs8::ToPublicKey;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::Digest;

const PUT_REQUEST_TAG: u8 = 0x00;
const POP_REQUEST_TAG: u8 = 0x01;

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

        Ok(pk.encrypt(&mut rng, padding, &cleartext)?)
    }
    fn decrypt(sk: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();

        Ok(sk.decrypt(padding, ciphertext)?)
    }
    fn sign(sk: &RsaPrivateKey, digest_in: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let hash = rsa::Hash::SHA2_256;
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(hash));
        let digest = sha2::Sha256::digest(digest_in).to_vec();

        Ok(sk.sign(padding, &digest)?)
    }
    fn verify(pk: &RsaPublicKey, digest_in: &Vec<u8>, sig: &[u8]) -> Result<(), Error> {
        let hash = rsa::Hash::SHA2_256;
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(hash));
        let digest = sha2::Sha256::digest(digest_in).to_vec();

        Ok(pk.verify(padding, &digest, sig)?)
    }
    fn serialize_put(
        public_key: Option<RsaPublicKey>,
        payload: Option<Vec<u8>>,
        surb: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, ()> {
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
                Err(_) => return Err(()),
                Ok(pem) => {
                    // When we have a pem, we also want to encrypt our payload & surb
                    if !payload.is_empty() {
                        payload = match Self::encrypt(&public_key, payload) {
                            Err(_) => return Err(()),
                            Ok(cyphertext) => cyphertext,
                        };
                    }
                    if !surb.is_empty() {
                        surb = match Self::encrypt(&public_key, surb) {
                            Err(_) => return Err(()),
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
    /// pk = delegation, sk = signature, wingman = destination
    fn serialize_pop(
        public_key: RsaPublicKey,
        secret_key: Option<RsaPrivateKey>,
        wingman: Vec<u8>,
    ) -> Result<Vec<u8>, ()> {
        // Only of type Option<> because the sk can't be deserialized
        // We do this here because it would look ugly in serialize()
        let secret_key = match secret_key {
            None => return Err(()),
            Some(secret_key) => secret_key,
        };

        let pem = match public_key.to_public_key_pem() {
            Err(_) => return Err(()),
            Ok(pem) => pem.as_bytes().to_vec(),
        };
        let pem_len_bytes = (pem.len() as u64).to_be_bytes();

        // Sign this
        let mut vector = std::iter::once(POP_REQUEST_TAG)
            .chain(wingman)
            .chain(pem_len_bytes)
            .chain(pem)
            .collect();

        let mut sig = match Self::sign(&secret_key, &vector) {
            Err(_) => return Err(()),
            Ok(sig) => sig,
        };
        let sig_len_bytes = (sig.len() as u64).to_be_bytes();

        vector.append(&mut sig_len_bytes.to_vec());
        vector.append(&mut sig);

        Ok(vector)
    }
    pub fn serialize(self) -> Result<Vec<u8>, ()> {
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
    fn deserialize_put(b: &[u8], secret_key: Option<&RsaPrivateKey>) -> Result<Self, ()> {
        if b.len() < 1 + 3 * std::mem::size_of::<u64>() {
            return Err(());
        }

        /* Extraction */
        let pem_len_bytes = u64::from_be_bytes(
            b[1..1 + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if pem_len_bytes > (b.len() - 1 - 3 * std::mem::size_of::<u64>()) as u64 {
            return Err(());
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
            return Err(());
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
            return Err(());
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
                                payload = match Self::decrypt(&sk, &given_payload) {
                                    Err(_) => return Err(()),
                                    Ok(cleartext) => Some(cleartext),
                                };
                            }
                        }
                        match surb {
                            None => {}
                            Some(given_surb) => {
                                surb = match Self::decrypt(&sk, &given_surb) {
                                    Err(_) => return Err(()),
                                    Ok(cleartext) => Some(cleartext),
                                };
                            }
                        }
                    }
                }

                // Convert pem
                match String::from_utf8(pem.to_owned()) {
                    Err(_) => return Err(()),
                    Ok(string) => {
                        match rsa::pkcs8::FromPublicKey::from_public_key_pem(string.as_str()) {
                            Err(_) => return Err(()),
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
    fn deserialize_pop(b: &[u8]) -> Result<Self, ()> {
        if b.len() < 97 + 2 * std::mem::size_of::<u64>() {
            return Err(());
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
            return Err(());
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
            return Err(());
        }
        let sig_bound = pem_bound + std::mem::size_of::<u64>() + sig_len_bytes as usize;
        let sig = &b[pem_bound + std::mem::size_of::<u64>()..sig_bound];

        /* Processing */
        let public_key = match String::from_utf8(pem.to_owned()) {
            Err(_) => return Err(()),
            Ok(string) => match rsa::pkcs8::FromPublicKey::from_public_key_pem(string.as_str()) {
                Err(_) => return Err(()),
                Ok(public_key) => public_key,
            },
        };

        let digest_in = std::iter::once(POP_REQUEST_TAG)
            .chain(wingman.to_vec())
            .chain(pem_len_bytes.to_be_bytes())
            .chain(pem.to_vec())
            .collect();

        match Self::verify(&public_key, &digest_in, sig) {
            Err(_) => Err(()),
            Ok(_) => Ok(ClientRequest::Pop {
                public_key,
                secret_key: None,
                wingman: wingman.to_vec(),
            }),
        }
    }
    pub fn deserialize(b: &[u8], sk: Option<&RsaPrivateKey>) -> Result<Self, ()> {
        if b.len() < std::mem::size_of::<u8>() {
            return Err(());
        }

        match b[0] {
            PUT_REQUEST_TAG => Self::deserialize_put(b, sk),
            POP_REQUEST_TAG => Self::deserialize_pop(b),
            _ => Err(()),
        }
    }
}
