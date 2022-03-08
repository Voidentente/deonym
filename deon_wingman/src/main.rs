use deonym::*;
use log::{error, info, warn};
use rsa::pkcs8::ToPublicKey;
use std::time::{Duration, Instant};

const MAX_SEEDS: u16 = 500;
const TIMEOUT: Duration = Duration::from_secs(10);
const GARBAGE_COLLECT_FREQ: u16 = 500;
const MAX_SUCCEEDING_ERR: u8 = 8;

struct Host {
    last_seen: Instant,
    queries: Vec<Vec<u8>>,
}

fn main() {
    let mut log_builder = pretty_env_logger::formatted_timed_builder();
    log_builder.filter(None, log::LevelFilter::Info);
    log_builder.init();

    info!("Initializing...");
    let mut client = match nym::NymClient::new() {
        Err(e) => {
            error!("Socket layer connection error, terminating: {}", e);
            error!("Is there a Nym client running on port 43615?");
            panic!("CONNECTION_INIT_ERR");
        }
        Ok(client) => client,
    };
    let mut this_address = Vec::<u8>::new();
    let mut hostmap = std::collections::HashMap::<String, Host>::new();
    let mut garbage_collect_ctr: u16 = 0;
    let mut succeeding_err_ctr: u8 = 0;

    let self_address_req = nym::ClientRequest::SelfAddress.serialize();
    match client.send_message(self_address_req) {
        Err(e) => {
            error!("Failed to self-address, terminating: {}", e);
            panic!("SELF_ADDRESS_ERR");
        }
        Ok(_) => {}
    }

    info!("Entering main handler");
    // Main handler
    loop {
        // Garbage collector
        if garbage_collect_ctr >= GARBAGE_COLLECT_FREQ {
            info!("Collecting garbage...");
            let mut keys_to_be_removed = Vec::<String>::new();
            for (key, host) in hostmap.iter() {
                if host.last_seen.elapsed() > TIMEOUT {
                    keys_to_be_removed.push(key.clone());
                }
            }
            info!("Removing {} entries...", keys_to_be_removed.len());
            for key in keys_to_be_removed {
                hostmap.remove(&key);
            }
            garbage_collect_ctr = 0;
            info!("Finished!");
        } else {
            garbage_collect_ctr += 1;
        }

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
                                info!("Self-address successful");
                            }
                            nym::ServerResponse::Received(nym_received) => {
                                // Deon layer
                                match deon::ClientRequest::deserialize(&nym_received.data, None) {
                                    Err(_) => warn!("Deon layer deserialization error, dismissing"),
                                    Ok(deon_message) => {
                                        // Deon handler
                                        match deon_message {
                                            deon::ClientRequest::Put {
                                                public_key,
                                                payload: _,
                                                surb: _,
                                            } => {
                                                // Put layer
                                                match public_key {
                                                    None => warn!("Put layer PK error, dismissing"),
                                                    Some(pk) => match pk.to_public_key_pem() {
                                                        Err(_) => {
                                                            warn!("Put layer PEM error, dismissing")
                                                        }
                                                        Ok(pem) => match hostmap.get_mut(&pem) {
                                                            None => {
                                                                warn!("Put layer unknown host error, dismissing");
                                                            }
                                                            Some(host) => {
                                                                if host.last_seen.elapsed()
                                                                    > TIMEOUT
                                                                {
                                                                    warn!("Put layer timeout error, dismissing");
                                                                } else {
                                                                    info!("Put successful");
                                                                    host.queries
                                                                        .push(nym_received.data);
                                                                }
                                                            }
                                                        },
                                                    },
                                                }
                                            }

                                            deon::ClientRequest::Pop {
                                                public_key,
                                                secret_key: _,
                                                wingman,
                                            } => {
                                                // Pop layer
                                                if this_address.is_empty() {
                                                    warn!("Pop layer no own address error, dismissing");
                                                } else {
                                                    if wingman != this_address {
                                                        warn!("Pop layer alien address error, dismissing");
                                                    } else {
                                                        if hostmap.len() as u16 >= MAX_SEEDS {
                                                            warn!("Pop layer max seed error, dismissing");
                                                        } else {
                                                            match public_key.to_public_key_pem() {
                                                                Err(_) => {
                                                                    warn!("Pop layer PEM error, dismissing")
                                                                }
                                                                Ok(pem) => {
                                                                    match nym_received.reply_surb {
                                                                        None => {
                                                                            warn!("Pop layer SURB error, dismissing");
                                                                        }
                                                                        Some(surb) => {
                                                                            match hostmap
                                                                                .get_mut(&pem)
                                                                            {
                                                                                None => {
                                                                                    hostmap.insert(
                                                                                pem.clone(),
                                                                                Host {
                                                                                    last_seen:
                                                                                        Instant::now(),
                                                                                    queries: Vec::<
                                                                                        Vec<u8>,
                                                                                    >::new(
                                                                                    ),
                                                                                },
                                                                            );
                                                                                }
                                                                                Some(host) => {
                                                                                    host.last_seen =
                                                                                        Instant::now();
                                                                                }
                                                                            }

                                                                            match hostmap
                                                                                .get_mut(&pem)
                                                                            {
                                                                                None => {
                                                                                    warn!("Pop layer database error, dismissing");
                                                                                }
                                                                                Some(host) => {
                                                                                    // Use this wingman addreess as redirect if needed
                                                                                    let deon_res = deon::ServerResponse::Pop {
                                                                                        payload: host.queries.clone(),
                                                                                        wingman: this_address.clone(),
                                                                                    }.serialize();
                                                                                    host.queries
                                                                                        .clear();
                                                                                    let nym_res = nym::ClientRequest::Reply {
                                                                                        data: deon_res,
                                                                                        reply_surb: surb,
                                                                                    }.serialize();
                                                                                    match client
                                                                                        .send_message(
                                                                                            nym_res,
                                                                                        ) {
                                                                                        Err(e) => {
                                                                                            warn!("Pop layer response error, dismissing: {}", e);
                                                                                        }
                                                                                        Ok(_) => {
                                                                                            info!("Pop successful");
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
                        }
                    }
                }
            }
        }
    }
}
