//! Discovery adapter facade.
//!
//! Discovery transports endpoints and authenticated peer observations; it
//! never grants membership or consensus authority.
pub mod adapters {
    mod discovery;
    pub use discovery::*;
}

pub use adapters::*;
