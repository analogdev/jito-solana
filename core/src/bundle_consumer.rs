use {
    crate::{
        banking_stage::committer::Committer,
        bundle_account_locker::{BundleAccountLocker, LockedBundle},
        bundle_stage::BundleStageLoopStats,
        bundle_stage_leader_stats::BundleStageLeaderStats,
        consensus_cache_updater::ConsensusCacheUpdater,
        immutable_deserialized_packet::DeserializedBundlePackets,
        proxy::block_engine_stage::BlockBuilderFeeInfo,
        qos_service::QosService,
        tip_manager::TipManager,
        unprocessed_transaction_storage::UnprocessedTransactionStorage,
    },
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::{measure, measure::Measure},
    solana_poh::poh_recorder::{BankStart, TransactionRecorder},
    solana_runtime::bank::Bank,
    solana_sdk::{
        bundle::{error::BundleExecutionError, sanitized::SanitizedBundle},
        clock::Slot,
        pubkey::Pubkey,
        timing::timestamp,
    },
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
        bundle_stage_loop_stats: &mut BundleStageLoopStats,
        bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    ) {
        self.maybe_update_blacklist(bank_start);

        // TODO (LB): if new slot, reserve block compute units and rebuffer the bundles that
        //  exceeded the cost model
        //  else, make sure to update the reserved compute cost
        // TODO (LB): execute bundles until empty or end of slot

        // let mut rebuffered_packet_count = 0;
        let mut consumed_buffered_packets_count = 0;
        // let mut consume_buffered_bundles_count = 0;
        let mut proc_start = Measure::start("consume_buffered_process");
        let num_bundles_to_process = unprocessed_transaction_storage.len();

        let reached_end_of_slot = unprocessed_transaction_storage.process_bundles(
            bank_start.working_bank.clone(),
            bundle_stage_loop_stats,
            bundle_stage_leader_stats,
            &self.blacklisted_accounts,
            |bundles, bundle_stage_leader_stats| {
                self.do_process_bundles(bundles, bank_start, bundle_stage_leader_stats)
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
        &self,
        bundles: &[(DeserializedBundlePackets, SanitizedBundle)],
        bank_start: &BankStart,
        bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    ) -> Vec<usize> {
        // BundleAccountLocker holds RW locks for ALL accounts in ALL transactions within a single bundle.
        // By pre-locking bundles before they're ready to be processed, it will prevent BankingStage from
        // grabbing those locks so BundleStage can process as fast as possible.
        // A LockedBundle is similar to TransactionBatch; once its dropped the locks are released.
        #[allow(clippy::needless_collect)]
        let (locked_bundle_results, locked_bundles_elapsed) = measure!(
            bundles
                .iter()
                .map(|(_, sanitized_bundle)| {
                    self.bundle_account_locker
                        .prepare_locked_bundle(sanitized_bundle, &bank_start.working_bank)
                })
                .collect::<Vec<_>>(),
            "locked_bundles_elapsed"
        );
        bundle_stage_leader_stats
            .bundle_stage_stats()
            .increment_locked_bundle_elapsed_us(locked_bundles_elapsed.as_us());

        // into_iter so that LockedBundles are dropped, releasing the locks from BankingStage
        let _execution_results: Vec<_> = locked_bundle_results
            .into_iter()
            .map(|r| match r {
                Ok(locked_bundle) => self.process_bundle(&locked_bundle, bank_start),
                Err(_e) => {
                    // TODO (LB): accumulate error, translate to another error
                    Ok(())
                }
            })
            .collect();

        // TODO (LB): loop through locked bundles
        vec![]
    }

    fn process_bundle(
        &self,
        locked_bundle: &LockedBundle,
        bank_start: &BankStart,
    ) -> Result<(), BundleExecutionError> {
        if !Bank::should_bank_still_be_processing_txs(
            &bank_start.bank_creation_time,
            bank_start.working_bank.ns_per_slot,
        ) {
            return Err(BundleExecutionError::PohMaxHeightError);
        }

        self.handle_tip_programs(locked_bundle, bank_start)?;

        // TODO (LB): can cache tip accounts somewhere

        Ok(())
    }

    fn handle_tip_programs(
        &self,
        locked_bundle: &LockedBundle,
        bank_start: &BankStart,
    ) -> Result<(), BundleExecutionError> {
        if !Self::bundle_touches_tip_pdas(
            locked_bundle.sanitized_bundle(),
            &self.tip_manager.get_tip_accounts(),
        ) || bank_start.working_bank.slot() == self.last_tip_update_slot
        {
            return Ok(());
        }

        //                         Self::maybe_initialize_tip_accounts(
        //                             bundle_account_locker,
        //                             bank_start,
        //                             cluster_info,
        //                             recorder,
        //                             transaction_status_sender,
        //                             gossip_vote_sender,
        //                             qos_service,
        //                             tip_manager,
        //                             max_bundle_retry_duration,
        //                             bundle_stage_leader_stats,
        //                             reserved_space,
        //                         )?;
        //
        //                         Self::maybe_change_tip_receiver(
        //                             bundle_account_locker,
        //                             bank_start,
        //                             cluster_info,
        //                             recorder,
        //                             transaction_status_sender,
        //                             gossip_vote_sender,
        //                             qos_service,
        //                             tip_manager,
        //                             max_bundle_retry_duration,
        //                             bundle_stage_leader_stats,
        //                             block_builder_fee_info,
        //                             reserved_space,
        //                         )?;
        //
        //                         *last_tip_update_slot = bank_start.working_bank.slot();

        Ok(())
    }

    /// Returns true if any of the transactions in a bundle mention one of the tip PDAs
    fn bundle_touches_tip_pdas(bundle: &SanitizedBundle, tip_pdas: &HashSet<Pubkey>) -> bool {
        bundle.transactions.iter().any(|tx| {
            tx.message()
                .account_keys()
                .iter()
                .any(|a| tip_pdas.contains(a))
        })
    }
}
