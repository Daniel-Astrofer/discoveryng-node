//! Identity domain facade.
//!
//! Key persistence is kept beside the identity model but isolated from the
//! discovery, membership and node runtime layers.
pub mod domain {
    mod identity;
    pub use identity::*;
}

pub use domain::*;
