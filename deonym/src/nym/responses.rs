use crate::nym::error::NymError;

const ERROR_RESPONSE_TAG: u8 = 0x00;
const RECEIVED_RESPONSE_TAG: u8 = 0x01;
const SELF_ADDRESS_RESPONSE_TAG: u8 = 0x02;

pub struct ReconstructedMessage {
    pub data: Vec<u8>,
    pub reply_surb: Option<Vec<u8>>,
}

pub enum ServerResponse {
    Received(ReconstructedMessage),
    SelfAddress(Vec<u8>),
}

impl ServerResponse {
    fn deserialize_received(b: &[u8]) -> Result<Self, NymError> {
        if b.len() < 2 + std::mem::size_of::<u64>() {
            return Err(NymError::MalformedError(format!(
                "Expected at least {} bytes, got {}",
                2 + std::mem::size_of::<u64>(),
                b.len()
            )));
        }

        let with_reply_surb = match b[1] {
            0 => false,
            1 => true,
            _ => {
                return Err(NymError::MalformedError(format!(
                    "Expected values {} or {} at with_reply_surb field, got {}",
                    0, 1, b[1]
                )))
            }
        };

        #[allow(clippy::branches_sharing_code)]
        if with_reply_surb {
            let reply_surb_len = u64::from_be_bytes(
                b[2..2 + std::mem::size_of::<u64>()]
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );

            if reply_surb_len > (b.len() - 2 + 2 * std::mem::size_of::<u64>()) as u64 {
                return Err(NymError::MalformedError(format!(
                    "Expected at most {} bytes for SURB, got {}",
                    b.len() - 2 + 2 * std::mem::size_of::<u64>(),
                    reply_surb_len
                )));
            }

            let surb_bound = 2 + std::mem::size_of::<u64>() + reply_surb_len as usize;

            let reply_surb_bytes = &b[2 + std::mem::size_of::<u64>()..surb_bound];

            let message_len = u64::from_be_bytes(
                b[surb_bound..surb_bound + std::mem::size_of::<u64>()]
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );

            let message = &b[surb_bound + std::mem::size_of::<u64>()..];

            if message.len() as u64 != message_len {
                return Err(NymError::MalformedError(format!(
                    "Expected message len of {} bytes, got {}",
                    message_len,
                    message.len()
                )));
            }

            Ok(ServerResponse::Received(ReconstructedMessage {
                data: message.to_vec(),
                reply_surb: Some(reply_surb_bytes.to_vec()),
            }))
        } else {
            let message_len = u64::from_be_bytes(
                b[2..2 + std::mem::size_of::<u64>()]
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );

            let message = &b[2 + std::mem::size_of::<u64>()..];

            if message.len() as u64 != message_len {
                return Err(NymError::MalformedError(format!(
                    "Expected message len of {} bytes, got {}",
                    message_len,
                    message.len(),
                )));
            }

            Ok(ServerResponse::Received(ReconstructedMessage {
                data: message.to_vec(),
                reply_surb: None,
            }))
        }
    }
    fn deserialize_self_address(b: &[u8]) -> Result<Self, NymError> {
        if b.len() != 97 {
            return Err(NymError::MalformedError(format!(
                "Expected 97 bytes, got {}",
                b.len()
            )));
        }

        Ok(ServerResponse::SelfAddress(b[1..].to_vec()))
    }
    pub fn deserialize(b: &[u8]) -> Result<Self, NymError> {
        if b.len() < std::mem::size_of::<u8>() {
            return Err(NymError::MalformedError(format!(
                "Expected at least 1 byte, got {}",
                b.len()
            )));
        }

        match b[0] {
            RECEIVED_RESPONSE_TAG => Self::deserialize_received(b),
            SELF_ADDRESS_RESPONSE_TAG => Self::deserialize_self_address(b),
            ERROR_RESPONSE_TAG => Err(NymError::ErrorResponse(format!(
                "Received Nym client error"
            ))),
            _ => Err(NymError::MalformedError(format!(
                "Expected tag {} or {} or {}, got {}",
                RECEIVED_RESPONSE_TAG, SELF_ADDRESS_RESPONSE_TAG, ERROR_RESPONSE_TAG, b[0]
            ))),
        }
    }
}
