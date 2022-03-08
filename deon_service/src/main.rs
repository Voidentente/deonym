//! This is a very simple **template** echo service.
//! It only shows how to interact with Deonym.

use deonym::*;
use log::{error, info, warn};
use rand::{thread_rng, Rng};
use rsa::pkcs8::FromPrivateKey;

// This is used to save Responses for
// when they can be send with a SURB
struct PendingResponse {
    payload: Option<Vec<u8>>,
    surb: Vec<u8>,
}

const ALLOW_STATEFUL: bool = true;
const MAX_SUCCEEDING_ERR: u8 = 8;

fn main() {
    let mut log_builder = pretty_env_logger::formatted_timed_builder();
    log_builder.filter(None, log::LevelFilter::Info);
    log_builder.init();

    // First, we need a connection to a Nym client.
    info!("Initializing...");
    let mut client = match nym::NymClient::new() {
        Err(e) => {
            error!("Socket layer connection error, terminating: {}", e);
            error!("Is there a Nym client running on port 43615?");
            panic!("CONNECTION_INIT_ERR");
        }
        Ok(client) => client,
    };

    // We also need to have a RSA keypair.
    // To generate one, you can use the deon key tool.
    let path = std::path::Path::new("./key.asc");
    let secret_key = rsa::RsaPrivateKey::read_pkcs8_pem_file(path).unwrap();
    let public_key = rsa::RsaPublicKey::from(&secret_key);

    let mut waiting_for_surb = Vec::<PendingResponse>::new();
    let mut secrets = Vec::<Vec<u8>>::new();
    let mut this_address = Vec::<u8>::new();
    let mut succeeding_err_ctr: u8 = 0;

    let self_address_req = nym::ClientRequest::SelfAddress.serialize();
    match client.send_message(self_address_req) {
        Err(e) => {
            error!("Failed to self-address, terminating: {}", e);
            panic!("SELF_ADDRESS_ERR");
        }
        Ok(_) => {}
    }

    // For simplicity, this is a echo server. This means that our response mimics the request.

    info!("Entering main handler");
    loop {
        // Socket layer
        match client.await_message() {
            Err(e) => {
                if succeeding_err_ctr >= MAX_SUCCEEDING_ERR {
                    error!("Socket layer connection lost, terminating");
                    panic!("CONNECTION_LOST_ERR")
                } else {
                    succeeding_err_ctr += 1;
                    warn!(
                        "Socket layer read error, dismissing ({} left before terminating): {}",
                        MAX_SUCCEEDING_ERR - succeeding_err_ctr,
                        e
                    );
                }
            }
            Ok(socket_message) => {
                // Nym layer
                match nym::ServerResponse::deserialize(&socket_message) {
                    Err(_) => warn!("Nym layer deserialization error, dismissing"),
                    Ok(nym_message) => {
                        // Nym handler
                        match nym_message {
                            nym::ServerResponse::SelfAddress(nym_address) => {
                                this_address = nym_address;
                            }
                            nym::ServerResponse::Received(nym_received) => {
                                // Deon layer
                                match deon::ServerResponse::deserialize(&nym_received.data) {
                                    Err(_) => warn!("Deon layer deserialization error, dismissing"),
                                    Ok(deon_message) => {
                                        // Deon handler
                                        match deon_message {
                                            deon::ServerResponse::Put { payload, surb: _ } => {
                                                // Put layer
                                                // Services could have outgoing PUT requests
                                                // (and therefore ingoing PUT responses), too.
                                                // This allows them to fetch stuff from other services.
                                                match nym_received.reply_surb {
                                                    None => {
                                                        // This is a reply to a Put request outgoing from this service
                                                    }
                                                    Some(own_surb) => {
                                                        // This might be a message we sent to ourself to generate a SURB
                                                        match waiting_for_surb.pop() {
                                                            None => {
                                                                // Well, this is awkward.
                                                                // Can't handle a response if there is none!
                                                            }
                                                            Some(pending_response) => {
                                                                match payload {
                                                                    None => {
                                                                        // In this case, the payload is the secret
                                                                        // and mandatory
                                                                    }
                                                                    Some(secret) => {
                                                                        for i in 0..secrets.len() {
                                                                            if secret == secrets[i]
                                                                            {
                                                                                secrets
                                                                                    .swap_remove(i);
                                                                                let put_res =
                                                                                deon::ServerResponse::Put {
                                                                                    payload: pending_response
                                                                                        .payload,
                                                                                    surb: Some(own_surb),
                                                                                }
                                                                                .serialize();
                                                                                let nym_req =
                                                                                nym::ClientRequest::Reply {
                                                                                    data: put_res,
                                                                                    reply_surb:
                                                                                        pending_response.surb,
                                                                                }
                                                                                .serialize();
                                                                                match client
                                                                                    .send_message(
                                                                                        nym_req,
                                                                                    ) {
                                                                                    Err(_) => {
                                                                                        warn!("Inner Pop layer response error, dismissing");
                                                                                    }
                                                                                    Ok(_) => {
                                                                                        info!("Succeessful SURB hoisting, hurray!");
                                                                                    }
                                                                                }
                                                                                break;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            deon::ServerResponse::Pop { payload, wingman } => {
                                                // Pop layer
                                                for inner in payload {
                                                    match deon::ClientRequest::deserialize(
                                                        &inner,
                                                        Some(&secret_key),
                                                    ) {
                                                        Err(_) => {
                                                            error!("Inner Pop layer deserialization error, dismissing")
                                                        }
                                                        Ok(inner_deon_message) => {
                                                            match inner_deon_message {
                                                                deon::ClientRequest::Pop {
                                                                    public_key: _,
                                                                    secret_key: _,
                                                                    wingman: _,
                                                                } => {
                                                                    // This has no functionality.
                                                                }
                                                                deon::ClientRequest::Put {
                                                                    public_key: _,
                                                                    payload,
                                                                    surb,
                                                                } => {
                                                                    match surb {
                                                                        None => {
                                                                            // Can't echo with no surb!
                                                                        }
                                                                        Some(surb) => {
                                                                            if ALLOW_STATEFUL {
                                                                                // We'll respond with SURB in Put layer
                                                                                let mut secret =
                                                                                    [0u8; 16];
                                                                                thread_rng().fill(
                                                                                    &mut secret[..],
                                                                                );
                                                                                let surb_hoist_req = deon::ServerResponse::Put {
                                                                                    payload: Some(secret.to_vec()),
                                                                                    surb: None,
                                                                                }.serialize();
                                                                                let nym_req = nym::ClientRequest::Send {
                                                                                    recipient: this_address.clone(),
                                                                                    data: surb_hoist_req,
                                                                                    with_reply_surb: true,
                                                                                }.serialize();
                                                                                match client
                                                                                    .send_message(
                                                                                        nym_req,
                                                                                    ) {
                                                                                    Err(_) => {
                                                                                        warn!("Inner Pop layer SURB hoisting error, dismissing");
                                                                                    }
                                                                                    Ok(_) => {
                                                                                        secrets.push(secret.to_vec());
                                                                                        waiting_for_surb
                                                                                            .push(PendingResponse { payload, surb });
                                                                                    }
                                                                                }
                                                                            } else {
                                                                                // We'll respond immediately without SURB
                                                                                let put_res =
                                                                                deon::ServerResponse::Put {
                                                                                    payload,
                                                                                    surb: None,
                                                                                }
                                                                                .serialize();
                                                                                let nym_req =
                                                                                nym::ClientRequest::Reply {
                                                                                    data: put_res,
                                                                                    reply_surb: surb,
                                                                                }
                                                                                .serialize();
                                                                                match client
                                                                                    .send_message(
                                                                                        nym_req,
                                                                                    ) {
                                                                                    Err(_) => {
                                                                                        warn!("Inner Pop layer response error, dismissing");
                                                                                    }
                                                                                    Ok(_) => {
                                                                                        // OK
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Then, repeat the heartbeat
                                                let pop_req = deon::ClientRequest::Pop {
                                                    public_key: public_key.clone(),
                                                    secret_key: Some(secret_key.clone()),
                                                    wingman: wingman.clone(),
                                                }
                                                .serialize();
                                                match pop_req {
                                                    Err(_) => {
                                                        // Serialization error => Can't do anything about it
                                                    }
                                                    Ok(pop_req) => {
                                                        let nym_req = nym::ClientRequest::Send {
                                                            recipient: wingman,
                                                            data: pop_req,
                                                            with_reply_surb: true,
                                                        }
                                                        .serialize();
                                                        match client.send_message(nym_req) {
                                                            Err(e) => {
                                                                // This isn't optimal
                                                                warn!("Heart-beat flat-lined, please restart: {}", e);
                                                            }
                                                            Ok(_) => {
                                                                // OK
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
