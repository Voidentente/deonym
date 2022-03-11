//! This is a very simple template echo service.
//! It should explain how to create a Deonym service.

use deonym::nym::NymClient;
use deonym::*;
use log::{error, info, warn};
use rand::{thread_rng, Rng};
use rsa::{pkcs8::FromPrivateKey, RsaPrivateKey, RsaPublicKey};

/// This struct holds pending responses that are waiting
/// for a reply SURB to become available.
struct PendingResponse {
    payload: Option<Vec<u8>>,
    surb: Vec<u8>,
}

/// This constant enables or disables stateful connections.
/// By default stateful connections are disabled, but consider
/// enabling them if you are hosting performance-critical stuff.
const ALLOW_STATEFUL: bool = true;

/// This constant limits how many errors in a row can occur
/// when trying to read from socket before the program is terminated
const MAX_SUCCEEDING_ERR: u8 = 8;

/// The SEED constants define on which Wingmen we want to seed.
/// Usually, you want to seed on 2 to 4 Wingmen at a time and not
/// change them too often. Here, we only seed on one Wingman.
/// TODO: Change this to a more flexible approach.
const SEED_1: [u8; 96] = [
    179, 67, 68, 104, 99, 156, 154, 109, 50, 63, 106, 34, 184, 160, 44, 59, 232, 178, 185, 26, 234,
    133, 141, 243, 163, 107, 147, 128, 78, 181, 149, 68, 211, 13, 86, 99, 103, 165, 176, 4, 227,
    39, 65, 237, 13, 92, 101, 122, 32, 230, 75, 174, 30, 29, 134, 255, 202, 127, 136, 235, 230,
    247, 91, 15, 79, 104, 57, 127, 94, 8, 81, 202, 162, 238, 100, 175, 161, 168, 117, 17, 208, 187,
    152, 37, 207, 37, 147, 230, 37, 243, 85, 73, 227, 71, 134, 172,
];

fn main() {
    let mut log_builder = pretty_env_logger::formatted_timed_builder();
    log_builder.filter(None, log::LevelFilter::Info);
    log_builder.init();

    info!("Initializing...");

    let mut client = match nym::NymClient::new() {
        Err(e) => {
            error!("Init error: Could not establish connection: {e}");
            panic!();
        }
        Ok(client) => client,
    };

    // Every Deonym service is identified by its RSA keypair.
    // To generate one, you can use the deon_key_tool.
    // Make sure to keep the keyfile secret!
    let path = std::path::Path::new("./key.asc");
    let secret_key = match rsa::RsaPrivateKey::read_pkcs8_pem_file(path) {
        Err(e) => {
            error!("Init error: Could not find keyfile: {e}");
            panic!();
        }
        Ok(sk) => sk,
    };
    let public_key = rsa::RsaPublicKey::from(&secret_key);

    let mut waiting_for_surb = Vec::<PendingResponse>::new();
    let mut secrets = Vec::<Vec<u8>>::new();
    let mut this_address = Vec::<u8>::new();
    let mut succeeding_err_ctr: u8 = 0;

    if let Err(e) = client.send_message(nym::ClientRequest::SelfAddress.serialize()) {
        error!("Init error: Could not send self-address: {e}");
        panic!();
    }

    // This block initiates the heartbeat with SEED_1
    let seed_1_deon_req = deon::ClientRequest::Pop {
        public_key: public_key.clone(),
        secret_key: Some(secret_key.clone()),
        wingman: SEED_1.to_vec(),
    }
    .serialize()
    .unwrap();
    let seed_1_nym_req = nym::ClientRequest::Send {
        recipient: SEED_1.to_vec(),
        data: seed_1_deon_req,
        with_reply_surb: true,
    }
    .serialize();
    client.send_message(seed_1_nym_req).unwrap();

    loop {
        // This may happen when e.g. the Nym client unexpectedly shuts down
        if succeeding_err_ctr >= MAX_SUCCEEDING_ERR {
            error!("Terminating: Too many errors");
            panic!();
        }

        handle(
            &mut client,
            &mut waiting_for_surb,
            &mut secrets,
            &mut this_address,
            &mut succeeding_err_ctr,
            &secret_key,
            &public_key,
        );
    }
}

fn handle(
    client: &mut NymClient,
    waiting_for_surb: &mut Vec<PendingResponse>,
    secrets: &mut Vec<Vec<u8>>,
    this_address: &mut Vec<u8>,
    ctr: &mut u8,
    secret_key: &RsaPrivateKey,
    public_key: &RsaPublicKey,
) {
    // Socket handler
    let socket_message = match client.await_message() {
        Err(e) => {
            *ctr += 1;
            warn!("Socket handler error: Could not read: {e}");
            return;
        }
        Ok(msg) => {
            *ctr = 0;
            msg
        }
    };

    // Nym layer
    let nym_message = match nym::ServerResponse::deserialize(&socket_message) {
        Err(e) => {
            warn!("Nym layer error: Could not deserialize: {e}");
            return;
        }
        Ok(msg) => msg,
    };

    // Nym handler
    let nym_received = match nym_message {
        nym::ServerResponse::SelfAddress(nym_address) => {
            *this_address = nym_address;
            info!("Init complete.");
            return;
        }
        nym::ServerResponse::Received(msg) => msg,
    };

    // Deon layer
    let deon_message = match deon::ServerResponse::deserialize(&nym_received.data) {
        Err(e) => {
            warn!("Deon layer error: Could not deserialize: {e}");
            return;
        }
        Ok(msg) => msg,
    };

    // Deon handler
    match deon_message {
        // Put layer
        deon::ServerResponse::Put { payload, surb: _ } => {
            // Put handler
            // Services could have outgoing PUT requests
            // (and therefore ingoing PUT responses), too.
            // This allows them to fetch stuff from other services.
            // This method is also used for SURB hoisting.
            match nym_received.reply_surb {
                None => {
                    // PUT responses from outgoing requests
                    // to other services land here
                    // Write your own code here
                }
                Some(own_surb) => {
                    // This might be a SURB hoist
                    let pending_response = match waiting_for_surb.pop() {
                        None => {
                            warn!("Put handler error: No response to hoist");
                            return;
                        }
                        Some(msg) => msg,
                    };

                    let secret = match payload {
                        None => {
                            warn!("Put handler error: Pending is missing secret");
                            return;
                        }
                        Some(secret) => secret,
                    };

                    // Check database for secret
                    for i in 0..secrets.len() {
                        if secret == secrets[i] {
                            // Security check passed
                            secrets.swap_remove(i);
                            let put_deon_res = deon::ServerResponse::Put {
                                payload: pending_response.payload,
                                surb: Some(own_surb),
                            }
                            .serialize();
                            let put_nym_res = nym::ClientRequest::Reply {
                                data: put_deon_res,
                                reply_surb: pending_response.surb,
                            }
                            .serialize();
                            if let Err(e) = client.send_message(put_nym_res) {
                                warn!("Put handler error: Response error: {e}");
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Pop layer
        deon::ServerResponse::Pop { payload, wingman } => {
            // Pop handler
            for inner in payload {
                handle_inner(
                    client,
                    secret_key,
                    this_address,
                    secrets,
                    waiting_for_surb,
                    inner,
                );
            }

            // Then, once everything is handled, repeat the heartbeat
            let pop_deon_req = deon::ClientRequest::Pop {
                public_key: public_key.clone(),
                secret_key: Some(secret_key.clone()),
                wingman: wingman.clone(),
            }
            .serialize();
            let pop_deon_req = match pop_deon_req {
                Err(e) => {
                    warn!("Pop handler error: Flatline: {e}");
                    return;
                }
                Ok(pop_deon_req) => pop_deon_req,
            };
            let pop_nym_req = nym::ClientRequest::Send {
                recipient: wingman,
                data: pop_deon_req,
                with_reply_surb: true,
            }
            .serialize();
            if let Err(e) = client.send_message(pop_nym_req) {
                warn!("Pop handler error: Flatline: {e}");
            }
        }
    }
}

fn handle_inner(
    client: &mut NymClient,
    secret_key: &RsaPrivateKey,
    this_address: &Vec<u8>,
    secrets: &mut Vec<Vec<u8>>,
    waiting_for_surb: &mut Vec<PendingResponse>,
    inner: Vec<u8>,
) {
    // Here you can handle pure requests
    // Again: This is a simple echo server implementation

    let inner_deon_message = match deon::ClientRequest::deserialize(&inner, Some(secret_key)) {
        Err(e) => {
            warn!("Inner handler error: Could not deserialize: {e}");
            return;
        }
        Ok(msg) => msg,
    };

    match inner_deon_message {
        // Inner Pop layer
        deon::ClientRequest::Pop {
            public_key: _,
            secret_key: _,
            wingman: _,
        } => {
            // Inner Pop handler
            // This has no functionality
        }

        // Inner Put layer
        deon::ClientRequest::Put {
            public_key: _,
            payload,
            surb,
        } => {
            // Inner Put handler
            // Here be your own handler
            // This example is a simple echo server
            let surb = match surb {
                None => {
                    warn!("Inner Put handler error: Can't echo without surb");
                    return;
                }
                Some(surb) => surb,
            };

            if ALLOW_STATEFUL {
                // We'll have to respond in Put layer
                let mut secret = [0u8; 16];
                thread_rng().fill(&mut secret[..]);
                let put_deon_res = deon::ServerResponse::Put {
                    payload: Some(secret.to_vec()),
                    surb: None,
                }
                .serialize();
                let put_nym_req = nym::ClientRequest::Send {
                    recipient: this_address.clone(),
                    data: put_deon_res,
                    with_reply_surb: true,
                }
                .serialize();

                match client.send_message(put_nym_req) {
                    Err(e) => {
                        warn!("Inner Put handler error: Could not send hoist: {e}");
                        return;
                    }
                    Ok(_) => {
                        secrets.push(secret.to_vec());
                        waiting_for_surb.push(PendingResponse { payload, surb });
                    }
                }
            } else {
                // We can respond directly
                let put_deon_res = deon::ServerResponse::Put {
                    payload,
                    surb: None,
                }
                .serialize();
                let put_nym_req = nym::ClientRequest::Reply {
                    data: put_deon_res,
                    reply_surb: surb,
                }
                .serialize();
                if let Err(e) = client.send_message(put_nym_req) {
                    warn!("Inner Put handler error: Could not send reply: {e}");
                }
            }
        }
    }
}
