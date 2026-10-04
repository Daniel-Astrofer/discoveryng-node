//! Discovery domain, ports, and adapters facade.
//!
//! Discovery transports endpoints and authenticated peer observations; it
//! never grants membership or consensus authority.
pub mod adapters;
pub mod domain;
pub mod ports;

pub use adapters::*;
pub use domain::*;
pub use ports::*;
