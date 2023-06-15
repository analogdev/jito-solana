use {
    crate::{
        banking_stage::{committer::Committer, BankingStageStats},
        bundle_account_locker::{BundleAccountLocker, LockedBundle},
        bundle_stage::BundleStageLoopStats,
        bundle_stage_leader_stats::BundleStageLeaderStats,
        consensus_cache_updater::ConsensusCacheUpdater,
        immutable_deserialized_packet::DeserializedBundlePackets,
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        proxy::block_engine_stage::BlockBuilderFeeInfo,
        qos_service::QosService,
        tip_manager::TipManager,
        unprocessed_transaction_storage::UnprocessedTransactionStorage,
    },
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::measure::Measure,
    solana_poh::poh_recorder::{BankStart, TransactionRecorder},
    solana_sdk::{clock::Slot, pubkey::Pubkey, timing::timestamp},
    std::{
        collections::HashSet,
        sync::{Arc, Mutex},
        time::Duration,
    },
};

// struct AllExecutionResults {
//     pub load_and_execute_tx_output: LoadAndExecuteTransactionsOutput,
//     pub sanitized_txs: Vec<SanitizedTransaction>,
//     pub pre_balances: (TransactionBalances, TransactionTokenBalances),
//     pub post_balances: (TransactionBalances, TransactionTokenBalances),
// }

pub struct BundleConsumer {
    committer: Committer,
    transaction_recorder: TransactionRecorder,
    qos_service: QosService,
    log_messages_bytes_limit: Option<usize>,

    consensus_cache_updater: ConsensusCacheUpdater,

    tip_manager: TipManager,
    last_tip_update_slot: Slot,

    blacklisted_accounts: HashSet<Pubkey>,

    // Manages account locks across multiple transactions within a bundle to prevent race conditions
    // with BankingStage
    bundle_account_locker: BundleAccountLocker,

    block_builder_fee_info: Arc<Mutex<BlockBuilderFeeInfo>>,

    max_bundle_retry_duration: Duration,

    cluster_info: Arc<ClusterInfo>,
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
        cluster_info: Arc<ClusterInfo>,
    ) -> Self {
        Self {
            committer,
            transaction_recorder,
            qos_service,
            log_messages_bytes_limit,
            consensus_cache_updater: ConsensusCacheUpdater::default(),
            tip_manager,
            last_tip_update_slot: Slot::default(),
            blacklisted_accounts: HashSet::default(),
            bundle_account_locker,
            block_builder_fee_info,
            max_bundle_retry_duration,
            cluster_info,
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
        &mut self,
        bank_start: &BankStart,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        bundle_stage_stats: &BundleStageLoopStats,
        bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    ) {
        self.maybe_update_blacklist(bank_start);

        // TODO (LB): if new slot, reserve block compute units and rebuffer the bundles that
        //  exceeded the cost model
        //  else, make sure to update the reserved compute cost
        // TODO (LB): execute bundles until empty or end of slot

        let mut rebuffered_packet_count = 0;
        let mut consumed_buffered_packets_count = 0;
        let mut consume_buffered_bundles_count = 0;
        let mut proc_start = Measure::start("consume_buffered_process");
        let num_bundles_to_process = unprocessed_transaction_storage.len();

        let reached_end_of_slot = unprocessed_transaction_storage.process_bundles(
            bank_start.working_bank.clone(),
            bundle_stage_stats,
            bundle_stage_leader_stats,
            &self.blacklisted_accounts,
            |deserialized_bundle_packets, bundle| {
                self.do_process_bundles(deserialized_bundle_packets, bundle)
            },
        );

        if reached_end_of_slot {
            bundle_stage_leader_stats
                .leader_slot_metrics_tracker()
                .set_end_of_slot_unprocessed_buffer_len(
                    unprocessed_transaction_storage.len() as u64
                );
        }

        proc_start.stop();
        debug!(
            "@{:?} done processing buffered bundles: {} time: {:?}ms tx count: {} tx/s: {}",
            timestamp(),
            num_bundles_to_process,
            proc_start.as_ms(),
            consumed_buffered_packets_count,
            (consumed_buffered_packets_count as f32) / (proc_start.as_s())
        );
    }

    /// Blacklist is updated with the tip payment program + any consensus accounts.
    fn maybe_update_blacklist(&mut self, bank_start: &BankStart) {
        if self
            .consensus_cache_updater
            .maybe_update(&bank_start.working_bank)
        {
            self.blacklisted_accounts = self
                .consensus_cache_updater
                .consensus_accounts_cache()
                .union(&HashSet::from_iter([self
                    .tip_manager
                    .tip_payment_program_id()]))
                .cloned()
                .collect();
        }
    }

    fn do_process_bundles(
        &mut self,
        deserialized_bundle_packets: &DeserializedBundlePackets,
        bundle: &LockedBundle,
    ) -> Option<Vec<usize>> {
        None
    }
}
