use solana_sdk::bundle::error::TipPaymentError;
use solana_sdk::bundle::sanitized::derive_bundle_id;
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
        &self,
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
        &mut self,
        bundles: &[(DeserializedBundlePackets, SanitizedBundle)],
        bank_start: &BankStart,
        bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    ) -> Vec<usize> {
        // BundleAccountLocker holds RW locks for ALL accounts in ALL transactions within a single bundle.
        // By pre-locking bundles before they're ready to be processed, it will prevent BankingStage from
        // grabbing those locks so BundleStage can process as fast as possible.
        // A LockedBundle is similar to TransactionBatch; once its dropped the locks are released.
        // #[allow(clippy::needless_collect)]
        // let (locked_bundle_results, locked_bundles_elapsed) = measure!(
        //     bundles
        //         .iter()
        //         .map(|(_, sanitized_bundle)| {
        //             self.bundle_account_locker
        //                 .prepare_locked_bundle(sanitized_bundle, &bank_start.working_bank)
        //         })
        //         .collect::<Vec<_>>(),
        //     "locked_bundles_elapsed"
        // );
        // bundle_stage_leader_stats
        //     .bundle_stage_stats()
        //     .increment_locked_bundle_elapsed_us(locked_bundles_elapsed.as_us());

        let locked_bundle_results = bundles
            .iter()
            .map(|(_, sanitized_bundle)| {
                self.bundle_account_locker
                    .prepare_locked_bundle(sanitized_bundle, &bank_start.working_bank)
            })
            .collect::<Vec<_>>();

        // // into_iter so that LockedBundles are dropped, releasing the locks from BankingStage
        // let _execution_results: Vec<_> = locked_bundle_results
        //     .into_iter()
        //     .map(|r| match r {
        //         Ok(locked_bundle) => self.process_bundle(&locked_bundle, bank_start),
        //         Err(e) => Err(BundleExecutionError::LockError),
        //     })
        //     .collect();

        // TODO (LB): accumulate the results into the stats
        vec![]
    }

    fn process_bundle(
        &mut self,
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

    /// The validator needs to manage state on two programs related to tips
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

        // This will setup the tip payment and tip distribution program if they haven't been
        // initialized yet, which is typically helpful for local validators. On mainnet and testnet,
        // this code should never run.
        if let Some(bundle) = self
            .tip_manager
            .get_initialize_tip_programs_bundle(&bank_start.working_bank, &self.cluster_info)
        {
            let locked_bundle = self
                .bundle_account_locker
                .prepare_locked_bundle(&bundle, &bank_start.working_bank)
                .map_err(|e| BundleExecutionError::TipError(TipPaymentError::LockError))?;

            // TODO (LB): execute it!
        }

        // There are two frequently run internal cranks inside the jito-solana validator that have to do with managing MEV tips.
        // One is initialize the TipDistributionAccount, which is a validator's "tip piggy bank" for an epoch
        // The other is ensuring the tip_receiver is configured correctly to ensure tips are routed to the correct
        // address. The validator must drain the tip accounts to the previous tip receiver before setting the tip receiver to
        // themselves.
        let tip_crank_bundle = self
            .tip_manager
            .get_tip_programs_crank_bundle(
                &bank_start.working_bank,
                &self.cluster_info,
                &self.block_builder_fee_info.lock().unwrap(),
            )
            .map_err(|e| BundleExecutionError::TipError(e))?;

        if let Some(bundle) = tip_crank_bundle {
            let locked_bundle = self
                .bundle_account_locker
                .prepare_locked_bundle(&bundle, &bank_start.working_bank)
                .map_err(|e| BundleExecutionError::TipError(TipPaymentError::LockError))?;

            // TODO (LB): execute it!
        }

        // self.last_tip_update_slot = bank_start.working_bank.slot();

        Ok(())
    }

    /// When executed the first time, there's some accounts that need to be initialized.
    /// This is only helpful for local testing, on testnet and mainnet these will never be executed.
    fn get_initialize_tip_programs_bundle(
        bank: &Bank,
        tip_manager: &TipManager,
        cluster_info: &Arc<ClusterInfo>,
    ) -> Option<SanitizedBundle> {
        let maybe_init_tip_payment_config_tx =
            if tip_manager.should_initialize_tip_payment_program(bank) {
                info!("building initialize_tip_payment_program_tx");
                Some(tip_manager.initialize_tip_payment_program_tx(
                    bank.last_blockhash(),
                    &cluster_info.keypair(),
                ))
            } else {
                None
            };

        let maybe_init_tip_distro_config_tx =
            if tip_manager.should_initialize_tip_distribution_config(bank) {
                info!("building initialize_tip_distribution_config_tx");
                Some(
                    tip_manager
                        .initialize_tip_distribution_config_tx(bank.last_blockhash(), cluster_info),
                )
            } else {
                None
            };

        let transactions = [
            maybe_init_tip_payment_config_tx,
            maybe_init_tip_distro_config_tx,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<SanitizedTransaction>>();

        if transactions.is_empty() {
            None
        } else {
            Some(SanitizedBundle {
                transactions,
                // TODO (LB): calculate this
                bundle_id: String::default(),
            })
        }
    }

    //     #[allow(clippy::too_many_arguments)]
    //     fn maybe_initialize_tip_accounts(
    //         bundle_account_locker: &BundleAccountLocker,
    //         bank_start: &BankStart,
    //         cluster_info: &Arc<ClusterInfo>,
    //         recorder: &TransactionRecorder,
    //         transaction_status_sender: &Option<TransactionStatusSender>,
    //         gossip_vote_sender: &ReplayVoteSender,
    //         qos_service: &QosService,
    //         tip_manager: &TipManager,
    //         max_bundle_retry_duration: &Duration,
    //         bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    //         reserved_space: &mut BundleReservedSpace,
    //     ) -> BundleStageResult<()> {
    //         let initialize_tip_accounts_bundle = SanitizedBundle {
    //             transactions: Self::get_initialize_tip_accounts_transactions(
    //                 &bank_start.working_bank,
    //                 tip_manager,
    //                 cluster_info,
    //             )?,
    //             bundle_id: String::default(),
    //         };
    //         if !initialize_tip_accounts_bundle.transactions.is_empty() {
    //             debug!("initialize tip account");
    //
    //             let locked_init_tip_bundle = bundle_account_locker
    //                 .prepare_locked_bundle(&initialize_tip_accounts_bundle, &bank_start.working_bank)
    //                 .map_err(|_| BundleExecutionError::LockError)?;
    //             let result = Self::update_qos_and_execute_record_commit_bundle(
    //                 locked_init_tip_bundle.sanitized_bundle(),
    //                 recorder,
    //                 transaction_status_sender,
    //                 gossip_vote_sender,
    //                 qos_service,
    //                 bank_start,
    //                 bundle_stage_leader_stats,
    //                 max_bundle_retry_duration,
    //                 reserved_space,
    //             );
    //
    //             match &result {
    //                 Ok(_) => {
    //                     debug!("initialize tip account: success");
    //                     bundle_stage_leader_stats
    //                         .bundle_stage_stats()
    //                         .increment_num_init_tip_account_ok(1);
    //                 }
    //                 Err(e) => {
    //                     error!("initialize tip account error: {:?}", e);
    //                     bundle_stage_leader_stats
    //                         .bundle_stage_stats()
    //                         .increment_num_init_tip_account_errors(1);
    //                 }
    //             }
    //             result
    //         } else {
    //             Ok(())
    //         }
    //     }
    //
    //     /// change tip receiver, draining tips to the previous tip_receiver in the process
    //     /// note that this needs to happen after the above tip-related bundle initializes
    //     /// config accounts because get_configured_tip_receiver relies on an account
    //     /// existing in the bank
    //     #[allow(clippy::too_many_arguments)]
    //     fn maybe_change_tip_receiver(
    //         bundle_account_locker: &BundleAccountLocker,
    //         bank_start: &BankStart,
    //         cluster_info: &Arc<ClusterInfo>,
    //         recorder: &TransactionRecorder,
    //         transaction_status_sender: &Option<TransactionStatusSender>,
    //         gossip_vote_sender: &ReplayVoteSender,
    //         qos_service: &QosService,
    //         tip_manager: &TipManager,
    //         max_bundle_retry_duration: &Duration,
    //         bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    //         block_builder_fee_info: &Arc<Mutex<BlockBuilderFeeInfo>>,
    //         reserved_space: &mut BundleReservedSpace,
    //     ) -> BundleStageResult<()> {
    //         let start_handle_tips = Instant::now();
    //
    //         let configured_tip_receiver =
    //             tip_manager.get_configured_tip_receiver(&bank_start.working_bank)?;
    //         let my_tip_distribution_pda =
    //             tip_manager.get_my_tip_distribution_pda(bank_start.working_bank.epoch());
    //         if configured_tip_receiver != my_tip_distribution_pda {
    //             info!(
    //                 "changing tip receiver from {} to {}",
    //                 configured_tip_receiver, my_tip_distribution_pda
    //             );
    //
    //             let bb_info = block_builder_fee_info.lock().unwrap();
    //             let change_tip_receiver_tx = tip_manager.change_tip_receiver_and_block_builder_tx(
    //                 &my_tip_distribution_pda,
    //                 &bank_start.working_bank,
    //                 &cluster_info.keypair(),
    //                 &bb_info.block_builder,
    //                 bb_info.block_builder_commission,
    //             )?;
    //
    //             let change_tip_receiver_bundle = SanitizedBundle {
    //                 transactions: vec![change_tip_receiver_tx],
    //                 bundle_id: String::default(),
    //             };
    //             let locked_change_tip_receiver_bundle = bundle_account_locker
    //                 .prepare_locked_bundle(&change_tip_receiver_bundle, &bank_start.working_bank)
    //                 .map_err(|_| BundleExecutionError::LockError)?;
    //             let result = Self::update_qos_and_execute_record_commit_bundle(
    //                 locked_change_tip_receiver_bundle.sanitized_bundle(),
    //                 recorder,
    //                 transaction_status_sender,
    //                 gossip_vote_sender,
    //                 qos_service,
    //                 bank_start,
    //                 bundle_stage_leader_stats,
    //                 max_bundle_retry_duration,
    //                 reserved_space,
    //             );
    //
    //             bundle_stage_leader_stats
    //                 .bundle_stage_stats()
    //                 .increment_change_tip_receiver_elapsed_us(
    //                     start_handle_tips.elapsed().as_micros() as u64
    //                 );
    //
    //             match &result {
    //                 Ok(_) => {
    //                     debug!("change tip receiver: success");
    //                     bundle_stage_leader_stats
    //                         .bundle_stage_stats()
    //                         .increment_num_change_tip_receiver_ok(1);
    //                 }
    //                 Err(e) => {
    //                     error!("change tip receiver: error {:?}", e);
    //                     bundle_stage_leader_stats
    //                         .bundle_stage_stats()
    //                         .increment_num_change_tip_receiver_errors(1);
    //                 }
    //             }
    //             result
    //         } else {
    //             Ok(())
    //         }
    //     }

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
