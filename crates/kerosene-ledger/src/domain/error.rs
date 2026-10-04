use crate::domain::account::StandardAccount;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
/// Reasons a ledger operation, synchronization, settlement, or policy check can fail.
pub enum LedgerError {
    #[error("unbalanced entry: debits {debits_sum} != credits {credits_sum}")]
    /// Journal debit and credit totals do not match.
    UnbalancedEntry {
        /// Sum of debit postings in the rejected entry.
        debits_sum: u128,
        /// Sum of credit postings in the rejected entry.
        credits_sum: u128,
    },

    #[error("entry must have at least one debit and one credit")]
    /// A journal entry has no debit or no credit posting.
    EmptyEntry,

    #[error("negative balance for {account:?}: {balance}")]
    /// Applying postings would make the account balance negative.
    NegativeBalance {
        /// Account whose resulting balance would be negative.
        account: StandardAccount,
        /// Rejected resulting balance in the ledger's smallest units.
        balance: i128,
    },

    #[error("duplicate sequence: {0}")]
    /// A journal sequence number has already been committed.
    DuplicateSequence(u64),

    #[error("sequence gap: expected {expected}, got {got}")]
    /// An entry arrived out of order relative to the expected sequence.
    SequenceGap {
        /// Next sequence number expected by the journal.
        expected: u64,
        /// Sequence number supplied by the rejected entry.
        got: u64,
    },

    #[error("account not found: {0:?}")]
    /// An operation references an account absent from the ledger state.
    AccountNotFound(StandardAccount),

    #[error("invalid hash: {0}")]
    /// A supplied hash has invalid syntax or length.
    InvalidHash(String),

    #[error("invariant violation: {0}")]
    /// A ledger state invariant failed validation.
    InvariantViolation(String),

    #[error("reserved {reserved} exceeds available {available}")]
    /// Requested reservation exceeds the account's available amount.
    ReservedExceedsAvailable {
        /// Amount requested for reservation.
        reserved: u64,
        /// Amount currently available to reserve.
        available: u64,
    },

    #[error("pending outgoing {outgoing} exceeds internal available {available}")]
    /// Pending outgoing transfers exceed internally available funds.
    PendingOutgoingExceedsAvailable {
        /// Total pending outgoing amount.
        outgoing: u64,
        /// Amount internally available after other holds.
        available: u64,
    },

    #[error("state version regression: previous {prev}, current {current}")]
    /// An update attempted to replace state with an older version.
    StateVersionRegression {
        /// Previously committed state version.
        prev: u64,
        /// Rejected replacement state version.
        current: u64,
    },

    #[error("balance overflow for account {account:?}")]
    /// Applying a credit would overflow the account balance representation.
    BalanceOverflow {
        /// Account whose balance exceeded its representable range.
        account: StandardAccount,
    },

    #[error("duplicate entry id: {0}")]
    /// A journal entry ID has already been used.
    DuplicateEntryId(String),

    // -----------------------------------------------------------------------
    // Wave 2 — Optimistic versioning, atomic reservations, durable idempotency
    // -----------------------------------------------------------------------
    #[error("version conflict: account {account} expected version {expected}, current {current}")]
    /// Optimistic concurrency check found a different account version.
    VersionConflict {
        /// Account ID whose version changed.
        account: String,
        /// Version supplied by the command.
        expected: u64,
        /// Version currently stored by the ledger.
        current: u64,
    },

    #[error("insufficient funds: account {account} has {available}, needs {needed}")]
    /// Account does not have enough available funds for the operation.
    InsufficientFunds {
        /// Account ID being debited or reserved.
        account: String,
        /// Available amount in the ledger's smallest units.
        available: u64,
        /// Required amount in the ledger's smallest units.
        needed: u64,
    },

    #[error("idempotency conflict: command {command_id} with different hash")]
    /// A previously seen command ID was reused with different semantic content.
    IdempotencyConflict {
        /// Reused command identifier with a different payload hash.
        command_id: String,
    },

    #[error("reservation not found: {0}")]
    /// The requested reservation ID does not exist.
    ReservationNotFound(String),

    #[error("reservation already consumed: {0}")]
    /// The reservation was already committed or otherwise consumed.
    ReservationAlreadyConsumed(String),

    #[error("reservation expired: {0}")]
    /// The requested reservation is past its expiry time.
    ReservationExpired(String),

    #[error("atomic transfer failed: {0}")]
    /// A transfer could not be committed atomically.
    AtomicTransferFailed(String),

    // -----------------------------------------------------------------------
    // Wave 3 — Deterministic state machine, state roots, certificates
    // -----------------------------------------------------------------------
    #[error("unknown command type: {0}")]
    /// The command type is not recognized by this state machine version.
    UnknownCommand(String),

    #[error("invalid state transition: {0}")]
    /// A command requests a transition that is not allowed from the current state.
    InvalidStateTransition(String),

    #[error("snapshot not found at sequence {0}")]
    /// No snapshot is available for the requested sequence.
    SnapshotNotFound(u64),

    #[error("invalid signature: {0}")]
    /// A command, vote, or certificate signature failed verification.
    InvalidSignature(String),

    #[error("state root mismatch: expected {expected}, got {got}")]
    /// Recomputed deterministic state root differs from the supplied root.
    StateRootMismatch {
        /// State root committed by the certificate or snapshot metadata.
        expected: String,
        /// State root recomputed from the received state.
        got: String,
    },

    // -----------------------------------------------------------------------
    // Wave 4 — Ordered replication, sync status, node recovery & membership
    // -----------------------------------------------------------------------
    #[error("sync not healthy: {0}")]
    /// Replication health is insufficient for the requested operation.
    SyncNotHealthy(String),

    #[error("node {node_id} is not a voter (role: {role:?})")]
    /// A node without a voting role attempted to cast a consensus vote.
    NotAVoter {
        /// ID of the non-voting node.
        node_id: String,
        /// Membership role currently assigned to that node.
        role: crate::consensus::membership::NodeRole,
    },

    #[error("cannot vote: {}", .reasons.join(", "))]
    /// One or more safety checks prevent the node from voting.
    CannotVote {
        /// Safety and eligibility checks that prevented the vote.
        reasons: Vec<String>,
    },

    #[error("node not found: {0}")]
    /// The requested node ID is absent from the membership view.
    NodeNotFound(String),

    #[error("invalid role transition: from {from:?} to {to:?}")]
    /// Membership role change violates the allowed role transition graph.
    InvalidRoleTransition {
        /// Existing role before the proposed transition.
        from: crate::consensus::membership::NodeRole,
        /// Requested role after the proposed transition.
        to: crate::consensus::membership::NodeRole,
    },

    // -----------------------------------------------------------------------
    // Wave 5 — UTXOs, chain observer, RBF, reorganizations
    // -----------------------------------------------------------------------
    #[error("utxo not found: {txid}:{vout}")]
    /// The referenced transaction output is not tracked by the ledger.
    UtxoNotFound {
        /// Transaction identifier containing the missing output.
        txid: String,
        /// Output index within the transaction.
        vout: u32,
    },

    #[error("invalid utxo transition: from {from:?} to {to:?}")]
    /// A UTXO state change is not permitted by the chain transition rules.
    InvalidUtxoTransition {
        /// Current on-chain UTXO state.
        from: crate::consensus::chain::OnchainState,
        /// Requested on-chain UTXO state.
        to: crate::consensus::chain::OnchainState,
    },

    #[error("utxo already reserved by {reserved_by}")]
    /// Another operation already holds a reservation for this UTXO.
    UtxoAlreadyReserved {
        /// Withdrawal or operation currently holding the reservation.
        reserved_by: String,
    },

    #[error("utxo not reserved")]
    /// An operation attempted to release or spend an unreserved UTXO.
    UtxoNotReserved,

    #[error("invalid utxo data: {0}")]
    /// UTXO metadata or detected chain data is malformed or inconsistent.
    InvalidUtxoData(String),

    // -----------------------------------------------------------------------
    // Wave 6 — Settlement authorization, PSBT binding, vault validation
    // -----------------------------------------------------------------------
    #[error("authorization expired at {expires_at}, current time {now}")]
    /// Settlement authorization is no longer valid at the current time.
    AuthorizationExpired {
        /// Unix timestamp at which the authorization ceased to be valid.
        expires_at: u64,
        /// Current validation timestamp.
        now: u64,
    },

    #[error("authorization invalid: {0}")]
    /// Settlement authorization failed identity, scope, or signature validation.
    AuthorizationInvalid(String),

    #[error("PSBT hash mismatch: expected {expected}, got {got}")]
    /// Submitted PSBT differs from the PSBT committed by the authorization.
    PsbtMismatch {
        /// PSBT digest committed in the authorization.
        expected: String,
        /// Digest of the submitted PSBT.
        got: String,
    },

    #[error("policy violation: {0}")]
    /// A settlement or withdrawal violates configured financial policy.
    PolicyViolation(String),

    #[error("withdrawal not found: {0}")]
    /// The requested withdrawal record does not exist.
    WithdrawalNotFound(String),

    // -----------------------------------------------------------------------
    // Wave 7 — Reconciliation, metrics, production gates
    // -----------------------------------------------------------------------
    #[error("gate blocked: {reason}")]
    /// A production or reconciliation gate rejected the operation.
    GateBlocked {
        /// Explanation of the production or reconciliation gate failure.
        reason: String,
    },
}
