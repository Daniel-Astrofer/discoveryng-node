//! Node service composition API.
//!
//! HTTP translation, lifecycle orchestration, consensus ports and runtime
//! wiring live in distinct internal modules. This facade preserves the stable
//! public API for the binary and integration tests.
pub mod api;
pub mod application;
pub mod bootstrap;
pub mod domain;

pub use application::*;
pub use bootstrap::run;
pub use domain::*;
