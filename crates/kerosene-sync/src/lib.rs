//! Lifecycle and external-state synchronization domain facade.
pub mod domain {
    mod lifecycle;
    pub use lifecycle::*;
}

pub use domain::*;
