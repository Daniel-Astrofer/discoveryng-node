//! Ledger use cases and operational application services.

/// Production readiness gates and degraded-mode decisions.
pub mod gates;
/// Operational ledger metrics collection.
pub mod metrics;
/// Read-only reconciliation of on-chain assets and ledger liabilities.
pub mod reconciliation;
/// Replication health, catch-up planning, and divergence recovery.
pub mod replication;

pub use gates::{DegradedMode, GateResult, ProductionGates};
pub use metrics::{BasicMetricsCollector, LedgerMetrics, MetricsCollector};
pub use reconciliation::{
    ReconciliationEngine, ReconciliationInputs, ReconciliationReport, ReconciliationStatus,
};
pub use replication::{
    can_vote, execute_catch_up, recover_divergence, CatchUpPlan, CatchUpStrategy, DivergenceReport,
    DivergenceResult, ReplicationStatus, SyncManager, SyncStatus, DIVERGENCE_CHECK_INTERVAL,
    MAX_REPLAY_COMMANDS,
};
