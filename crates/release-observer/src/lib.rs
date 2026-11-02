//! Authenticated Bank release reads and durable observer anti-replay state.
//! No ledger dependencies and no consensus authority.
mod service;
mod transport;

pub use service::*;
pub use transport::{BankEndpoint, BankTransport};
