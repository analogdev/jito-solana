use crate::bundle_stage::BundleStageLoopStats;
use crate::bundle_stage_leader_stats::BundleStageLeaderStats;
use {
    crate::{
        banking_stage::{committer::Committer, BankingStageStats},
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        qos_service::QosService,
        unprocessed_transaction_storage::UnprocessedTransactionStorage,
    },
    solana_poh::poh_recorder::{BankStart, TransactionRecorder},
};

pub struct BundleConsumer {
    committer: Committer,
    transaction_recorder: TransactionRecorder,
    qos_service: QosService,
    log_messages_bytes_limit: Option<usize>,
}

impl BundleConsumer {
    pub fn new(
        committer: Committer,
        transaction_recorder: TransactionRecorder,
        qos_service: QosService,
        log_messages_bytes_limit: Option<usize>,
    ) -> Self {
        Self {
            committer,
            transaction_recorder,
            qos_service,
            log_messages_bytes_limit,
        }
    }

    pub fn consume_buffered_bundles(
        &self,
        bank_start: &BankStart,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        bundle_stage_stats: &BundleStageLoopStats,
        bundle_stage_leader_stats: &mut BundleStageLeaderStats,
    ) {
    }
}
