use itertools::max;
use solana_measure::measure_us;
use solana_sdk::bundle::error::TipPaymentError;
use solana_sdk::bundle::sanitized::derive_bundle_id;
use solana_sdk::bundle::utils::BundleExecutionResult;
use solana_sdk::transaction::SanitizedTransaction;
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

pub struct BundleReservedSpace {
    pub(crate) current_tx_block_limit: u64,
    pub(crate) current_bundle_block_limit: u64,
    pub(crate) initial_allocated_cost: u64,
    pub(crate) unreserved_ticks: u64,
}

// impl BundleReservedSpace {
//     fn reset_reserved_cost(&mut self, working_bank: &Arc<Bank>) {
//         self.current_tx_block_limit = self
//             .current_bundle_block_limit
//             .saturating_sub(self.initial_allocated_cost);
//
//         working_bank
//             .write_cost_tracker()
//             .unwrap()
//             .set_block_cost_limit(self.current_tx_block_limit);
//
//         debug!(
//             "slot: {}. cost limits reset. bundle: {}, txn: {}",
//             working_bank.slot(),
//             self.current_bundle_block_limit,
//             self.current_tx_block_limit,
//         );
//     }
//
//     fn bundle_block_limit(&self) -> u64 {
//         self.current_bundle_block_limit
//     }
//
//     fn tx_block_limit(&self) -> u64 {
//         self.current_tx_block_limit
//     }
//
//     fn update_reserved_cost(&mut self, working_bank: &Arc<Bank>) {
//         if self.current_tx_block_limit != self.current_bundle_block_limit
//             && working_bank
//                 .max_tick_height()
//                 .saturating_sub(working_bank.tick_height())
//                 < self.unreserved_ticks
//         {
//             self.current_tx_block_limit = self.current_bundle_block_limit;
//             working_bank
//                 .write_cost_tracker()
//                 .unwrap()
//                 .set_block_cost_limit(self.current_tx_block_limit);
//             debug!(
//                 "slot: {}. increased tx cost limit to {}",
//                 working_bank.slot(),
//                 self.current_tx_block_limit
//             );
//         }
//     }
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

    reserved_space: BundleReservedSpace,
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
        reserved_space: BundleReservedSpace,
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
            reserved_space,
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
            &self.blacklisted_accounts.clone(),
            |bundles, bundle_stage_leader_stats| {
                Self::do_process_bundles(
                    &self.bundle_account_locker,
                    &self.tip_manager,
                    &mut self.last_tip_update_slot,
                    &self.cluster_info,
                    &self.block_builder_fee_info,
                    &self.committer,
                    &self.transaction_recorder,
                    &self.qos_service,
                    &self.log_messages_bytes_limit,
                    self.max_bundle_retry_duration,
                    bundles,
                    bank_start,
                    bundle_stage_leader_stats,
                )
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
        bundle_account_locker: &BundleAccountLocker,
        tip_manager: &TipManager,
        last_tip_updated_slot: &mut Slot,
        cluster_info: &Arc<ClusterInfo>,
        block_builder_fee_info: &Arc<Mutex<BlockBuilderFeeInfo>>,
        committer: &Committer,
        recorder: &TransactionRecorder,
        qos_service: &QosService,
        log_messages_bytes_limit: &Option<usize>,
        max_bundle_retry_duration: Duration,
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
                    bundle_account_locker
                        .prepare_locked_bundle(sanitized_bundle, &bank_start.working_bank)
                })
                .collect::<Vec<_>>(),
            "locked_bundles_elapsed"
        );
        bundle_stage_leader_stats
            .bundle_stage_stats()
            .increment_locked_bundle_elapsed_us(locked_bundles_elapsed.as_us());

        // // into_iter so that LockedBundles are dropped, releasing the locks from BankingStage
        let _execution_results: Vec<_> = locked_bundle_results
            .into_iter()
            .map(|r| match r {
                Ok(locked_bundle) => Self::process_bundle(
                    bundle_account_locker,
                    tip_manager,
                    last_tip_updated_slot,
                    cluster_info,
                    block_builder_fee_info,
                    committer,
                    recorder,
                    qos_service,
                    log_messages_bytes_limit,
                    max_bundle_retry_duration,
                    &locked_bundle,
                    bank_start,
                ),
                Err(_) => Err(BundleExecutionError::LockError),
            })
            .collect();

        // TODO (LB): accumulate the results into the stats
        vec![]
    }

    fn process_bundle(
        bundle_account_locker: &BundleAccountLocker,
        tip_manager: &TipManager,
        last_tip_updated_slot: &mut Slot,
        cluster_info: &Arc<ClusterInfo>,
        block_builder_fee_info: &Arc<Mutex<BlockBuilderFeeInfo>>,
        committer: &Committer,
        recorder: &TransactionRecorder,
        qos_service: &QosService,
        log_messages_bytes_limit: &Option<usize>,
        max_bundle_retry_duration: Duration,
        locked_bundle: &LockedBundle,
        bank_start: &BankStart,
    ) -> Result<(), BundleExecutionError> {
        if !Bank::should_bank_still_be_processing_txs(
            &bank_start.bank_creation_time,
            bank_start.working_bank.ns_per_slot,
        ) {
            return Err(BundleExecutionError::PohMaxHeightError);
        }

        if Self::bundle_touches_tip_pdas(
            locked_bundle.sanitized_bundle(),
            &tip_manager.get_tip_accounts(),
        ) && bank_start.working_bank.slot() != *last_tip_updated_slot
        {
            Self::handle_tip_programs(
                bundle_account_locker,
                tip_manager,
                last_tip_updated_slot,
                cluster_info,
                block_builder_fee_info,
                committer,
                recorder,
                qos_service,
                log_messages_bytes_limit,
                max_bundle_retry_duration,
                bank_start,
            )?;

            *last_tip_updated_slot = bank_start.working_bank.slot();
        }

        Self::update_qos_and_execute_record_commit_bundle(
            committer,
            recorder,
            qos_service,
            log_messages_bytes_limit,
            max_bundle_retry_duration,
            locked_bundle.sanitized_bundle(),
            bank_start,
        )?;

        Ok(())
    }

    /// The validator needs to manage state on two programs related to tips
    fn handle_tip_programs(
        bundle_account_locker: &BundleAccountLocker,
        tip_manager: &TipManager,
        last_tip_updated_slot: &mut Slot,
        cluster_info: &Arc<ClusterInfo>,
        block_builder_fee_info: &Arc<Mutex<BlockBuilderFeeInfo>>,
        committer: &Committer,
        recorder: &TransactionRecorder,
        qos_service: &QosService,
        log_messages_bytes_limit: &Option<usize>,
        max_bundle_retry_duration: Duration,
        bank_start: &BankStart,
    ) -> Result<(), BundleExecutionError> {
        // This will setup the tip payment and tip distribution program if they haven't been
        // initialized yet, which is typically helpful for local validators. On mainnet and testnet,
        // this code should never run.
        if let Some(bundle) =
            tip_manager.get_initialize_tip_programs_bundle(&bank_start.working_bank, cluster_info)
        {
            info!(
                "initializing tip programs with #{} transactions",
                bundle.transactions.len()
            );
            let locked_init_tip_programs_bundle = bundle_account_locker
                .prepare_locked_bundle(&bundle, &bank_start.working_bank)
                .map_err(|e| BundleExecutionError::TipError(TipPaymentError::LockError))?;

            // TODO (LB): execute it and map error to tip error
            // Self::update_qos_and_execute_record_commit_bundle()
        }

        // There are two frequently run internal cranks inside the jito-solana validator that have to do with managing MEV tips.
        // One is initialize the TipDistributionAccount, which is a validator's "tip piggy bank" for an epoch
        // The other is ensuring the tip_receiver is configured correctly to ensure tips are routed to the correct
        // address. The validator must drain the tip accounts to the previous tip receiver before setting the tip receiver to
        // themselves.
        let tip_crank_bundle = tip_manager
            .get_tip_programs_crank_bundle(
                &bank_start.working_bank,
                cluster_info,
                &block_builder_fee_info.lock().unwrap(),
            )
            .map_err(|e| BundleExecutionError::TipError(e))?;

        if let Some(bundle) = tip_crank_bundle {
            info!(
                "cranking tip programs with #{} transactions",
                bundle.transactions.len()
            );
            let locked_tip_crank_bundle = bundle_account_locker
                .prepare_locked_bundle(&bundle, &bank_start.working_bank)
                .map_err(|e| BundleExecutionError::TipError(TipPaymentError::LockError))?;

            // TODO (LB): execute it and map errors to tip error
            // Self::update_qos_and_execute_record_commit_bundle()
        }

        Ok(())
    }

    /// Foo
    fn update_qos_and_execute_record_commit_bundle(
        committer: &Committer,
        recorder: &TransactionRecorder,
        qos_service: &QosService,
        log_messages_bytes_limit: &Option<usize>,
        max_bundle_retry_duration: Duration,
        sanitized_bundle: &SanitizedBundle,
        bank_start: &BankStart,
    ) -> BundleExecutionResult<()> {
        // TODO (LB): reserve blockspace, if not enough then bail

        let (
            (transaction_qos_cost_results, cost_model_throttled_transactions_count),
            cost_model_us,
        ) = measure_us!(qos_service.select_and_accumulate_transaction_costs(
            &bank_start.working_bank,
            &sanitized_bundle.transactions,
            std::iter::repeat(Ok(()))
        ));

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
