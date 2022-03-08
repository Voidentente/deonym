const SEND_REQUEST_TAG: u8 = 0x00;
const REPLY_REQUEST_TAG: u8 = 0x01;
const SELF_ADDRESS_REQUEST_TAG: u8 = 0x02;

pub enum ClientRequest {
    Send {
        recipient: Vec<u8>,
        data: Vec<u8>,
        with_reply_surb: bool,
    },
    Reply {
        data: Vec<u8>,
        reply_surb: Vec<u8>,
    },
    SelfAddress,
}

impl ClientRequest {
    fn serialize_send(recipient: Vec<u8>, data: Vec<u8>, with_reply_surb: bool) -> Vec<u8> {
        let data_len_bytes = (data.len() as u64).to_be_bytes();

        std::iter::once(SEND_REQUEST_TAG)
            .chain(std::iter::once(with_reply_surb as u8))
            .chain(recipient.iter().cloned())
            .chain(data_len_bytes.iter().cloned())
            .chain(data.into_iter())
            .collect()
    }
    fn serialize_reply(data: Vec<u8>, reply_surb: Vec<u8>) -> Vec<u8> {
        let data_len_bytes = (data.len() as u64).to_be_bytes();
        let surb_len_bytes = (reply_surb.len() as u64).to_be_bytes();

        std::iter::once(REPLY_REQUEST_TAG)
            .chain(surb_len_bytes.iter().cloned())
            .chain(reply_surb.into_iter())
            .chain(data_len_bytes.iter().cloned())
            .chain(data.into_iter())
            .collect()
    }
    fn serialize_self_address() -> Vec<u8> {
        std::iter::once(SELF_ADDRESS_REQUEST_TAG).collect()
    }
    pub fn serialize(self) -> Vec<u8> {
        match self {
            ClientRequest::Send {
                recipient,
                data,
                with_reply_surb,
            } => Self::serialize_send(recipient, data, with_reply_surb),

            ClientRequest::Reply { data, reply_surb } => Self::serialize_reply(data, reply_surb),

            ClientRequest::SelfAddress => Self::serialize_self_address(),
        }
    }
}
