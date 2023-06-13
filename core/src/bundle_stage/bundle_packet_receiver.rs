use {
    super::BundleStageLoopStats,
    crate::{
        banking_trace::BankingPacketReceiver,
        bundle_stage::bundle_packet_deserializer::{
            BundlePacketDeserializer, ReceiveBundleResults,
        },
        immutable_deserialized_packet::{DeserializedBundlePackets, ImmutableDeserializedPacket},
        leader_slot_banking_stage_metrics::LeaderSlotMetricsTracker,
        packet_bundle::PacketBundle,
        packet_deserializer::{PacketDeserializer, ReceivePacketResults},
        tracer_packet_stats::TracerPacketStats,
        unprocessed_transaction_storage::UnprocessedTransactionStorage,
    },
    crossbeam_channel::{Receiver, RecvTimeoutError},
    solana_measure::{measure::Measure, measure_us},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::{saturating_add_assign, timing::timestamp},
    std::{
        sync::{atomic::Ordering, Arc, RwLock},
        time::Duration,
    },
};

pub struct BundleReceiver {
    id: u32,
    bundle_packet_deserializer: BundlePacketDeserializer,
}

impl BundleReceiver {
    pub fn new(
        id: u32,
        bundle_packet_receiver: Receiver<Vec<PacketBundle>>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        Self {
            id,
            bundle_packet_deserializer: BundlePacketDeserializer::new(
                bundle_packet_receiver,
                bank_forks,
            ),
        }
    }

    /// Receive incoming packets, push into unprocessed buffer with packet indexes
    pub fn receive_and_buffer_bundles(
        &mut self,
        unprocessed_bundle_storage: &mut UnprocessedTransactionStorage,
        bundle_stage_stats: &mut BundleStageLoopStats,
    ) -> Result<(), RecvTimeoutError> {
        let (result, recv_time_us) = measure_us!({
            let recv_timeout = Self::get_receive_timeout(unprocessed_bundle_storage);
            let mut recv_and_buffer_measure = Measure::start("recv_and_buffer");
            self.bundle_packet_deserializer
                .receive_bundles(recv_timeout, unprocessed_bundle_storage.max_receive_size())
                // Consumes results if Ok, otherwise we keep the Err
                .map(|receive_bundle_results| {
                    self.buffer_bundles(
                        receive_bundle_results,
                        unprocessed_bundle_storage,
                        bundle_stage_stats,
                        // tracer_packet_stats,
                        // slot_metrics_tracker,
                    );
                    recv_and_buffer_measure.stop();
                    bundle_stage_stats
                        .receive_and_buffer_bundles_elapsed_us
                        .fetch_add(recv_and_buffer_measure.as_us(), Ordering::Relaxed);
                })
        });

        // slot_metrics_tracker.increment_receive_and_buffer_packets_us(recv_time_us);

        result
    }

    fn get_receive_timeout(
        unprocessed_transaction_storage: &UnprocessedTransactionStorage,
    ) -> Duration {
        // Gossip thread will almost always not wait because the transaction storage will most likely not be empty
        if !unprocessed_transaction_storage.is_empty() {
            // If there are buffered packets, run the equivalent of try_recv to try reading more
            // packets. This prevents starving BankingStage::consume_buffered_packets due to
            // buffered_packet_batches containing transactions that exceed the cost model for
            // the current bank.
            Duration::from_millis(0)
        } else {
            // BundleStage should pick up a working_bank as fast as possible
            Duration::from_millis(100)
        }
    }

    fn buffer_bundles(
        &self,
        ReceiveBundleResults {
            deserialized_bundles,
            num_dropped_bundles,
            num_dropped_packets,
        }: ReceiveBundleResults,
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        bundle_stage_stats: &mut BundleStageLoopStats,
        // slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        let bundle_count = deserialized_bundles.len();
        let packet_count: usize = deserialized_bundles.iter().map(|b| b.packets.len()).sum();
        debug!(
            "@{:?} bundles: {} txs: {} id: {}",
            timestamp(),
            bundle_count,
            packet_count,
            self.id
        );

        // Track all the packets incoming from sigverify, both valid and invalid
        // slot_metrics_tracker.increment_total_new_valid_packets(passed_sigverify_count);
        // slot_metrics_tracker.increment_newly_failed_sigverify_count(failed_sigverify_count);

        let mut dropped_packets_count = 0;
        let mut dropped_bundles_count = 0;
        let mut newly_buffered_bundles_count = 0;
        let mut newly_buffered_packets_count = 0;
        Self::push_unprocessed(
            unprocessed_transaction_storage,
            deserialized_bundles,
            &mut dropped_packets_count,
            &mut dropped_bundles_count,
            &mut newly_buffered_bundles_count,
            &mut newly_buffered_packets_count,
            // bundle_stage_stats,
            // slot_metrics_tracker,
            // tracer_packet_stats,
        );

        bundle_stage_stats
            .num_bundles_received
            .fetch_add(bundle_count, Ordering::Relaxed);
        bundle_stage_stats
            .num_packets_received
            .fetch_add(packet_count, Ordering::Relaxed);

        bundle_stage_stats
            .newly_buffered_bundles_count
            .fetch_add(newly_buffered_bundles_count, Ordering::Relaxed);
        bundle_stage_stats
            .newly_buffered_packets_count
            .fetch_add(newly_buffered_packets_count, Ordering::Relaxed);

        bundle_stage_stats
            .current_buffered_bundles_count
            .swap(unprocessed_transaction_storage.len(), Ordering::Relaxed);

        // TODO (LB): add current_buffered_bundles_count and current_buffered_packets_count
        // bundle_stage_stats
        //     .current_buffered_packets_count
        //     .swap(unprocessed_transaction_storage.iter(), Ordering::Relaxed);

        bundle_stage_stats
            .num_bundles_dropped
            .fetch_add(dropped_bundles_count, Ordering::Relaxed);
        bundle_stage_stats
            .num_packets_dropped
            .fetch_add(dropped_packets_count, Ordering::Relaxed);
    }

    fn push_unprocessed(
        unprocessed_transaction_storage: &mut UnprocessedTransactionStorage,
        deserialized_bundles: Vec<DeserializedBundlePackets>,
        dropped_packets_count: &mut usize,
        dropped_bundles_count: &mut usize,
        newly_buffered_bundles_count: &mut usize,
        newly_buffered_packets_count: &mut usize,
        // bundle_stage_stats: &mut BundleStageLoopStats,
        // slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
        // tracer_packet_stats: &mut TracerPacketStats,
    ) {
        if !deserialized_bundles.is_empty() {
            // let _ = banking_stage_stats
            //     .batch_packet_indexes_len
            //     .increment(deserialized_packets.len() as u64);

            *newly_buffered_bundles_count += deserialized_bundles.len();
            // slot_metrics_tracker
            //     .increment_newly_buffered_packets_count(deserialized_packets.len() as u64);

            let insert_bundles_summary =
                unprocessed_transaction_storage.insert_bundles(deserialized_bundles);
            // slot_metrics_tracker
            //     .accumulate_insert_packet_batches_summary(&insert_packet_batches_summary);
            // saturating_add_assign!(
            //     *dropped_packets_count,
            //     insert_packet_batches_summary.total_dropped_packets()
            // );
            // tracer_packet_stats.increment_total_exceeded_banking_stage_buffer(
            //     insert_packet_batches_summary.dropped_tracer_packets(),
            // );
        }
    }
}
