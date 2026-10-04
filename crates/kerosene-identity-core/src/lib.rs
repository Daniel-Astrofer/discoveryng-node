//! Identity domain and persistence facade.
//!
//! Key persistence is kept in adapters while the pure identity model and
//! crypto verification remain in domain.
pub mod adapters;
pub mod domain;

pub use adapters::*;
pub use domain::*;
