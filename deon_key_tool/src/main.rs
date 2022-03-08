//! This is a simple tool that generates a
//! RSA keypair for use in Deonym services.

use rand::rngs::OsRng;
use rsa::{pkcs8::ToPrivateKey, RsaPrivateKey};
use std::path::Path;

fn main() {
    let bit_size = 4096;
    let sk_path = Path::new("./key.asc");
    let mut rng = OsRng;
    println!("Beginning key generation, this might take a while...");
    let sk = RsaPrivateKey::new(&mut rng, bit_size).expect("Error generating keypair");
    sk.write_pkcs8_pem_file(sk_path)
        .expect("Error writing key to path");
    println!("Finished!");
}
