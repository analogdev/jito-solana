use {
    crate::{
        banking_stage::{committer::Committer, BankingStageStats},
        bundle_account_locker::BundleAccountLocker,
        bundle_stage::BundleStageLoopStats,
        bundle_stage_leader_stats::BundleStageLeaderStats,
        consensus_cache_updater::ConsensusCacheUpdater,
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        proxy::block_engine_stage::BlockBuilderFeeInfo,
        qos_service::QosService,
        tip_manager::TipManager,
        unprocessed_transaction_storage::UnprocessedTransactionStorage,
    },
    solana_poh::poh_recorder::{BankStart, TransactionRecorder},
    solana_sdk::clock::Slot,
    std::{
        collections::HashSet,
        sync::{Arc, Mutex},
        time::Duration,
    },
};

pub struct BundleConsumer {
    committer: Committer,
    transaction_recorder: TransactionRecorder,
    qos_service: QosService,
    log_messages_bytes_limit: Option<usize>,

    consensus_cache_updater: ConsensusCacheUpdater,
    tip_manager: TipManager,
    // Manages account locks across multiple transactions within a bundle to prevent race conditions
    // with BankingStage
    bundle_account_locker: BundleAccountLocker,

    block_builder_fee_info: Arc<Mutex<BlockBuilderFeeInfo>>,

    max_bundle_retry_duration: Duration,

    last_tip_update_slot: Slot,
}

impl BundleConsumer {
    pub fn new(
        committer: Committer,
        transaction_recorder: TransactionRecorder,
        qos_service: QosService,
        log_messages_bytes_limit: Option<usize>,
        tip_manager: TipManager,
        bundle_account_locker: BundleAccountLocker,
        block_builder_fee_info: Arc<Mutex<BlockBuilderFeeInfo>>,
        max_bundle_retry_duration: Duration,
    ) -> Self {
        Self {
            committer,
            transaction_recorder,
            qos_service,
            log_messages_bytes_limit,
            consensus_cache_updater: ConsensusCacheUpdater::default(),
            tip_manager,
            bundle_account_locker,
            block_builder_fee_info,
            max_bundle_retry_duration,
            last_tip_update_slot: Slot::default(),
        }
    }

    // A bundle is a series of transactions to be executed sequentially, atomically, and all-or-nothing.
    // Sequentially:
    //  - Transactions are executed in order
    // Atomically:
    //  - All transactions in a bundle get recoded to PoH and committed to the bank in the same slot. Account locks
    //  for all accounts in all transactions in a bundle are held during the entire execution to remove POH record race conditions
    //  with transactions in BankingStage.
    // All-or-nothing:
    //  - All transactions are committed or none. Modified state for the entire bundle isn't recorded to PoH and committed to the
    //  bank until all transactions in the bundle have executed.
    //
    // Some corner cases to be aware of when working with BundleStage:
    // A bundle is not allowed to call the Tip Payment program in a bundle (or BankingStage).
    // - This is to avoid stealing of tips by malicious parties with bundles that crank the tip
    // payment program and set the tip receiver to themself.
    // A bundle is not allowed to touch consensus-related accounts
    //  - This is to avoid stalling the voting BankingStage threads.
    pub fn consume_buffered_bundles(
        &self,
        bank_start: &BankStart,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        bundle_stage_stats: &BundleStageLoopStats,
        bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    ) {
    }
}
