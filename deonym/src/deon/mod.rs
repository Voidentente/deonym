/*
 *  Deonym's library for its own little protocol, Deon.
 *  Currently only for serialization/deserialization.
 */

mod error;
mod requests;
mod responses;

pub use requests::ClientRequest;
pub use responses::ServerResponse;
