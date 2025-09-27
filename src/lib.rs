pub mod netguard;
pub mod cache;
mod cstream;
mod socks;
pub mod netguard_client;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

// pub use netguard::{NetGuard, dummy_netguard::DummyNetGuard};
pub use cstream::CStream;
pub use socks::{SocksClient, User, AuthMethods, Merino};
pub use netguard_client::NetGuardClient;
