//! Synchronization domain, ports, and adapters facade.
//!
//! Node lifecycle advancement and snapshot verification live in domain;
//! persistence and transport adapters live in adapters and ports.
pub mod adapters;
pub mod domain;
pub mod ports;

pub use adapters::*;
pub use domain::*;
pub use ports::*;
