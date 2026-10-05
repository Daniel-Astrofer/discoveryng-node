//! Canonical state-root and integrity calculations.

/// Canonical hashing of complete deterministic ledger state.
pub mod state_root;

pub use state_root::compute_state_root;
