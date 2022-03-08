//! This is a simple tool that prints a Nym
//! client's unencoded address for debugging.

use deonym::*;

fn main() {
    let mut client = nym::NymClient::new().unwrap();
    let self_address_req = nym::ClientRequest::SelfAddress.serialize();
    client.send_message(self_address_req).unwrap();

    let self_address_res = client.await_message().unwrap();
    let this_address = match nym::ServerResponse::deserialize(&self_address_res) {
        Err(_) => panic!("Failed to deserialize"),
        Ok(nym_response) => match nym_response {
            nym::ServerResponse::Received(_) => panic!("Wrong type received"),
            nym::ServerResponse::SelfAddress(nym_address) => nym_address,
        },
    };
    println!("The decoded address of this client is:");
    println!("{:?}", this_address);
    client.close().unwrap();
}
