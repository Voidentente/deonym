const PUT_RESPONSE_TAG: u8 = 0x00;
const POP_RESPONSE_TAG: u8 = 0x01;

use crate::deon::error::DeonError;

pub enum ServerResponse {
    Put {
        payload: Option<Vec<u8>>,
        surb: Option<Vec<u8>>,
    },
    Pop {
        payload: Vec<Vec<u8>>,
        wingman: Vec<u8>,
    },
}

impl ServerResponse {
    /// Payload: (Optional) Any data,
    /// SURB: (Optional) SURB of target client
    fn serialize_put(payload: Option<Vec<u8>>, surb: Option<Vec<u8>>) -> Vec<u8> {
        let payload = match payload {
            None => Vec::<u8>::new(),
            Some(payload) => payload,
        };

        let surb = match surb {
            None => Vec::<u8>::new(),
            Some(surb) => surb,
        };

        let payload_len_bytes = (payload.len() as u64).to_be_bytes();
        let surb_len_bytes = (surb.len() as u64).to_be_bytes();

        std::iter::once(PUT_RESPONSE_TAG)
            .chain(payload_len_bytes)
            .chain(payload)
            .chain(surb_len_bytes)
            .chain(surb)
            .collect()
    }
    /// Payload: Vector of PUT requests for target,
    /// Wingman: This Wingman's Nym address
    fn serialize_pop(payload: Vec<Vec<u8>>, wingman: Vec<u8>) -> Vec<u8> {
        let block_size = (payload.len() as u64).to_be_bytes();

        let mut vec: Vec<u8> = std::iter::once(POP_RESPONSE_TAG)
            .chain(wingman)
            .chain(block_size)
            .collect();

        for mut inner in payload {
            vec.append(&mut (inner.len() as u64).to_be_bytes().to_vec());
            vec.append(&mut inner);
        }

        return vec;
    }
    /// Serialize the response for transport over network
    pub fn serialize(self) -> Vec<u8> {
        match self {
            ServerResponse::Put { payload, surb } => Self::serialize_put(payload, surb),

            ServerResponse::Pop { payload, wingman } => Self::serialize_pop(payload, wingman),
        }
    }
    /// b: Binary data to deserialize
    fn deserialize_put(b: &[u8]) -> Result<Self, DeonError> {
        if b.len() < 1 + 2 * std::mem::size_of::<u64>() {
            return Err(DeonError::MalformedError(format!(
                "Expected at least {} bytes, got {}",
                1 + 2 * std::mem::size_of::<u64>(),
                b.len()
            )));
        }

        /* Extraction */
        let payload_len_bytes = u64::from_be_bytes(
            b[1..1 + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if payload_len_bytes > (b.len() - 1 - 2 * std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::MalformedError(format!(
                "Expected at most {} bytes for payload, got {}",
                b.len() - 1 - 2 * std::mem::size_of::<u64>(),
                payload_len_bytes
            )));
        }
        let payload_bound = 1 + std::mem::size_of::<u64>() + payload_len_bytes as usize;
        let payload = &b[1 + std::mem::size_of::<u64>()..payload_bound];

        let surb_len_bytes = u64::from_be_bytes(
            b[payload_bound..payload_bound + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        );
        if surb_len_bytes > (b.len() - payload_bound - std::mem::size_of::<u64>()) as u64 {
            return Err(DeonError::MalformedError(format!(
                "Expected at most {} bytes for SURB, got {}",
                b.len() - payload_bound - std::mem::size_of::<u64>(),
                surb_len_bytes
            )));
        }
        let surb_bound = payload_bound + std::mem::size_of::<u64>() + surb_len_bytes as usize;
        let surb = &b[payload_bound + std::mem::size_of::<u64>()..surb_bound];

        /* Processing */
        let payload = match payload.is_empty() {
            true => None,
            false => Some(payload.to_vec()),
        };
        let surb = match surb.is_empty() {
            true => None,
            false => Some(surb.to_vec()),
        };

        Ok(ServerResponse::Put { payload, surb })
    }
    /// b: Binary data to deserialize
    fn deserialize_pop(b: &[u8]) -> Result<Self, DeonError> {
        if b.len() < 97 + std::mem::size_of::<u64>() {
            return Err(DeonError::MalformedError(format!(
                "Expected at least {} bytes, got {}",
                97 + std::mem::size_of::<u64>(),
                b.len()
            )));
        }

        /* Extraction */
        let wingman = &b[1..97];

        let block_size = u64::from_be_bytes(
            b[97..97 + std::mem::size_of::<u64>()]
                .as_ref()
                .try_into()
                .unwrap(),
        ) as usize;

        let mut payload: Vec<Vec<u8>> = Vec::new();

        let mut ptr = 97 + std::mem::size_of::<u64>();

        for i in 0..block_size {
            let block_len_bytes = u64::from_be_bytes(
                b[ptr..ptr + std::mem::size_of::<u64>()]
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );
            if block_len_bytes
                > (b.len() - ptr - (block_size - i) * std::mem::size_of::<u64>()) as u64
            {
                return Err(DeonError::MalformedError(format!(
                    "Expected at most {} bytes for block size, got {}",
                    b.len() - ptr - (block_size - i) * std::mem::size_of::<u64>(),
                    block_len_bytes
                )));
            }
            let block_bound = ptr + std::mem::size_of::<u64>() + block_len_bytes as usize;
            let block = &b[ptr + std::mem::size_of::<u64>()..block_bound];

            ptr = block_bound;
            payload.push(block.to_vec());
        }

        Ok(ServerResponse::Pop {
            payload,
            wingman: wingman.to_vec(),
        })
    }
    /// Deserialize the response for use in program
    pub fn deserialize(b: &[u8]) -> Result<Self, DeonError> {
        if b.len() < 1 {
            return Err(DeonError::MalformedError(format!(
                "Expected at least {} byte, got {}",
                1,
                b.len()
            )));
        }

        match b[0] {
            PUT_RESPONSE_TAG => Ok(Self::deserialize_put(b)?),
            POP_RESPONSE_TAG => Ok(Self::deserialize_pop(b)?),
            _ => Err(DeonError::MalformedError(format!(
                "Expected tag {} or {}, got {}",
                PUT_RESPONSE_TAG, POP_RESPONSE_TAG, b[0]
            ))),
        }
    }
}
