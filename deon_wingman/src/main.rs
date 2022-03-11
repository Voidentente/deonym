use deonym::nym::NymClient;
use deonym::*;
use log::{error, info, warn};
use rsa::pkcs8::ToPublicKey;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// This constant limits how many hosts we can seed,
/// (specifically NOT how many heartbeats there can be)
const MAX_SEEDS: u16 = 500;

/// This constant defines how frequent we garbage collect the map,
/// it should be around the same as MAX_SEEDS
const GARBAGE_COLLECT_FREQ: u16 = 500;

/// This constant defines when we consider a seed abandoned,
/// so we no longer accept incoming Puts and can remove the entry
const DURATION_UNTIL_ABANDONED: Duration = Duration::from_secs(10);

/// This constant limits how many errors in a row can occur
/// when trying to read from socket before the program is terminated
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

    let mut client = match NymClient::new() {
        Err(e) => {
            error!("Init error: Could not establish conncetion: {e}");
            panic!();
        }
        Ok(client) => client,
    };

    let mut hostmap = HashMap::<String, Host>::new();
    let mut this_address = Vec::<u8>::new();

    let mut garbage_collect_ctr: u16 = 0;
    let mut succeeding_err_ctr: u8 = 0;

    if let Err(e) = client.send_message(nym::ClientRequest::SelfAddress.serialize()) {
        error!("Init error: Could not send self-address: {e}");
        panic!();
    }

    loop {
        // This may happen when e.g. the Nym client unexpectedly shuts down
        if succeeding_err_ctr >= MAX_SUCCEEDING_ERR {
            error!("Terminating: Too many errors");
            panic!();
        }

        garbage_collect_round(&mut hostmap, &mut garbage_collect_ctr);

        handle(
            &mut client,
            &mut hostmap,
            &mut this_address,
            &mut succeeding_err_ctr,
        );
    }
}

fn garbage_collect_round(hostmap: &mut HashMap<String, Host>, ctr: &mut u16) {
    if *ctr >= GARBAGE_COLLECT_FREQ {
        info!("Collecting garbage...");
        let t = Instant::now();
        let mut keys_to_be_removed = Vec::<String>::new();
        for (key, host) in hostmap.iter() {
            if host.last_seen.elapsed() > DURATION_UNTIL_ABANDONED {
                keys_to_be_removed.push(key.clone());
            }
        }
        let len = keys_to_be_removed.len();
        for key in keys_to_be_removed {
            hostmap.remove(&key);
        }
        *ctr = 0;
        info!("Done removing {} dead entries in {:?}", len, t.elapsed());
    } else {
        *ctr += 1;
    }
}

fn handle(
    client: &mut NymClient,
    hostmap: &mut HashMap<String, Host>,
    this_address: &mut Vec<u8>,
    ctr: &mut u8,
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
    let deon_message = match deon::ClientRequest::deserialize(&nym_received.data, None) {
        Err(e) => {
            warn!("Deon layer error: Could not deserialize: {e}");
            return;
        }
        Ok(msg) => msg,
    };

    // Deon handler
    match deon_message {
        // Put layer
        deon::ClientRequest::Put {
            public_key,
            payload: _,
            surb: _,
        } => {
            // Put handler
            let public_key = match public_key {
                None => {
                    warn!("Put handler error: Public key missing");
                    return;
                }
                Some(public_key) => public_key,
            };

            let pem = match public_key.to_public_key_pem() {
                Err(e) => {
                    warn!("Put handler error: Failed to create PEM from pk: {e}");
                    return;
                }
                Ok(pem) => pem,
            };

            let host = match hostmap.get_mut(&pem) {
                None => {
                    warn!("Put handler error: Target host unknown");
                    return;
                }
                Some(host) => host,
            };

            if host.last_seen.elapsed() > DURATION_UNTIL_ABANDONED {
                warn!("Put handler error: Target host abandoned");
            } else {
                host.queries.push(nym_received.data);
            }
        }

        // Pop layer
        deon::ClientRequest::Pop {
            public_key,
            secret_key: _,
            wingman,
        } => {
            // Pop handler
            if this_address.is_empty() {
                warn!("Pop handler error: Self address missing");
                return;
            } else if wingman != *this_address {
                warn!("Pop handler error: Alien target address");
                return;
            }

            let pem = match public_key.to_public_key_pem() {
                Err(e) => {
                    warn!("Pop handler error: Failed to create PEM from pk: {e}");
                    return;
                }
                Ok(pem) => pem,
            };

            let surb = match nym_received.reply_surb {
                None => {
                    warn!("Pop handler error: Reply surb missing");
                    return;
                }
                Some(surb) => surb,
            };

            // Database update
            match hostmap.get_mut(&pem) {
                None => {
                    // Target host is unknown
                    if hostmap.len() as u16 >= MAX_SEEDS {
                        warn!("Pop handler error: Max seeds reached");
                        return;
                    }
                    hostmap.insert(
                        pem.clone(),
                        Host {
                            last_seen: Instant::now(),
                            queries: Vec::<Vec<u8>>::new(),
                        },
                    );
                }
                Some(host) => {
                    // Target host is known
                    host.last_seen = Instant::now();
                }
            }

            let host = match hostmap.get_mut(&pem) {
                None => {
                    warn!("Pop handler error: Database error");
                    return;
                }
                Some(host) => host,
            };

            let deon_res = deon::ServerResponse::Pop {
                payload: host.queries.clone(),
                wingman: this_address.clone(),
            }
            .serialize();

            host.queries.clear();

            let nym_res = nym::ClientRequest::Reply {
                data: deon_res,
                reply_surb: surb,
            }
            .serialize();

            if let Err(e) = client.send_message(nym_res) {
                warn!("Pop handler error: Write error: {e}");
            }
        }
    }
}
