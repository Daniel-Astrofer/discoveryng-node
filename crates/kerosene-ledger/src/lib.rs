//! Deterministic, double-entry financial ledger and persistence adapters.
//!
//! The crate exposes domain rules, state-machine commands, consensus evidence,
//! and storage ports used by node services to apply and verify ledger updates.

pub mod adapters;
pub mod application;
pub mod consensus;
pub mod domain;
pub mod integrity;
pub mod ports;

pub use adapters::*;
pub use application::*;
pub use consensus::*;
pub use domain::*;
pub use integrity::*;
pub use ports::*;

#[cfg(test)]
mod tests;
