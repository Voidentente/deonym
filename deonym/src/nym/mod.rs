/*
 *  Deonym's socket library for communicating with the Nym client.
 *  Somewhat close to Nym's implementation.
 *  See Nym's source code for original implementation details.
 */

mod client;
mod requests;
mod responses;

pub use client::NymClient;
pub use requests::ClientRequest;
pub use responses::ServerResponse;
