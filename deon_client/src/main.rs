//! This is a very simple **template** client.
//! It only shows how to interact with Deonym.

use deonym::*;
use rand::{thread_rng, Rng};
use rsa::pkcs8::FromPrivateKey;

const WINGMAN_1: [u8; 96] = [
    179, 67, 68, 104, 99, 156, 154, 109, 50, 63, 106, 34, 184, 160, 44, 59, 232, 178, 185, 26, 234,
    133, 141, 243, 163, 107, 147, 128, 78, 181, 149, 68, 211, 13, 86, 99, 103, 165, 176, 4, 227,
    39, 65, 237, 13, 92, 101, 122, 32, 230, 75, 174, 30, 29, 134, 255, 202, 127, 136, 235, 230,
    247, 91, 15, 79, 104, 57, 127, 94, 8, 81, 202, 162, 238, 100, 175, 161, 168, 117, 17, 208, 187,
    152, 37, 207, 37, 147, 230, 37, 243, 85, 73, 227, 71, 134, 172,
];

fn main() {
    let mut client = nym::NymClient::new().unwrap();
    let payload = Some("Hello World!".as_bytes().to_vec());

    // Generate SURB

    let self_address_req = nym::ClientRequest::SelfAddress.serialize();
    client.send_message(self_address_req).unwrap();
    let self_address_res = client.await_message().unwrap();
    let this_address = match nym::ServerResponse::deserialize(&self_address_res).unwrap() {
        nym::ServerResponse::Received(_) => {
            panic!("This example is linear and has no main handler, hence this is unlikely")
        }
        nym::ServerResponse::SelfAddress(this_address) => this_address,
    };

    let mut secret = [0u8; 16];
    thread_rng().fill(&mut secret[..]);

    let surb_req = nym::ClientRequest::Send {
        recipient: this_address,
        data: secret.to_vec(),
        with_reply_surb: true,
    }
    .serialize();
    client.send_message(surb_req).unwrap();
    let surb_res = client.await_message().unwrap();
    let surb = match nym::ServerResponse::deserialize(&surb_res).unwrap() {
        nym::ServerResponse::Received(msg) => match msg.reply_surb {
            None => {
                panic!("This example is linear and has no main handler, hence this is unlikely")
            }
            Some(surb) => {
                // Important
                if msg.data == secret {
                    Some(surb)
                } else {
                    panic!("This example is linear and has no main handler, hence this is unlikely")
                }
            }
        },
        nym::ServerResponse::SelfAddress(_) => {
            panic!("This example is linear and has no main handler, hence this is unlikely")
        }
    };

    // Send to service

    let path = std::path::Path::new("./key.asc");
    let secret_key = rsa::RsaPrivateKey::read_pkcs8_pem_file(path).unwrap();
    let public_key = Some(rsa::RsaPublicKey::from(&secret_key));

    let deon_req = deon::ClientRequest::Put {
        public_key,
        payload,
        surb,
    }
    .serialize()
    .unwrap();
    let nym_req = nym::ClientRequest::Send {
        recipient: WINGMAN_1.to_vec(),
        data: deon_req,
        with_reply_surb: false,
    }
    .serialize();
    client.send_message(nym_req).unwrap();

    // Wait for response

    let nym_res = match nym::ServerResponse::deserialize(&client.await_message().unwrap()).unwrap()
    {
        nym::ServerResponse::Received(msg) => msg.data,
        nym::ServerResponse::SelfAddress(_) => {
            panic!("This example is linear and has no main handler, hence this is unlikely")
        }
    };
    let deon_res = deon::ServerResponse::deserialize(&nym_res).unwrap();
    match deon_res {
        deon::ServerResponse::Pop {
            payload: _,
            wingman: _,
        } => panic!("This example is linear and has no main handler, hence this is unlikely"),

        deon::ServerResponse::Put { payload, surb } => {
            match payload {
                None => {
                    // No payload
                    println!("Received no payload");
                }
                Some(payload) => {
                    // Some payload to handle
                    // In this case, we know it's good utf8:
                    println!("Received payload: {}", String::from_utf8(payload).unwrap());
                }
            }
            match surb {
                None => {
                    // Service doesn't allow stateful connections. Bad luck ¯\_(ツ)_/¯
                    println!("Service does not allow stateful connections");
                }
                Some(surb) => {
                    // From now on, a stateful connection can be used
                    println!("Service allows stateful connections: {:?}", surb);
                }
            }
        }
    }
}
