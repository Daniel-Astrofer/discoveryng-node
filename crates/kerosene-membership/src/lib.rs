//! Deterministic membership domain facade.
pub mod domain {
    mod membership;
    pub use membership::*;
}

pub use domain::*;
