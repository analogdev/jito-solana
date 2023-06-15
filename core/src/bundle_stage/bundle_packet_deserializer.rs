//! Deserializes PacketBundles
use {
    crate::{
        immutable_deserialized_packet::{DeserializedBundleError, DeserializedBundlePackets},
        packet_bundle::PacketBundle,
    },
    crossbeam_channel::{Receiver, RecvTimeoutError},
    solana_runtime::bank_forks::BankForks,
    solana_sdk::saturating_add_assign,
    std::{
        sync::{Arc, RwLock},
        time::{Duration, Instant},
    },
};

/// Results from deserializing packet batches.
pub struct ReceiveBundleResults {
    /// Deserialized bundles from all received bundle packets
    pub deserialized_bundles: Vec<DeserializedBundlePackets>,
    /// Number of dropped bundles
    pub num_dropped_bundles: usize,
    /// Number of dropped packets
    pub num_dropped_packets: usize,
}

pub struct BundlePacketDeserializer {
    /// Receiver for bundle packets
    bundle_packet_receiver: Receiver<Vec<PacketBundle>>,
    /// Provides working bank for deserializer to check feature activation
    bank_forks: Arc<RwLock<BankForks>>,
}

impl BundlePacketDeserializer {
    pub fn new(
        bundle_packet_receiver: Receiver<Vec<PacketBundle>>,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> Self {
        Self {
            bundle_packet_receiver,
            bank_forks,
        }
    }

    /// Handles receiving bundles and deserializing them
    pub fn receive_bundles(
        &self,
        recv_timeout: Duration,
        capacity: usize,
    ) -> Result<ReceiveBundleResults, RecvTimeoutError> {
        let (bundle_count, _packet_count, mut bundles) =
            self.receive_until(recv_timeout, capacity)?;

        // Note: this can be removed after feature `round_compute_unit_price` is activated in
        // mainnet-beta
        let _working_bank = self.bank_forks.read().unwrap().working_bank();
        let round_compute_unit_price_enabled = false; // TODO get from working_bank.feature_set

        Ok(Self::deserialize_and_collect_bundles(
            bundle_count,
            &mut bundles,
            round_compute_unit_price_enabled,
        ))
    }

    /// Deserialize packet batches, aggregates tracer packet stats, and collect
    /// them into ReceivePacketResults
    fn deserialize_and_collect_bundles(
        bundle_count: usize,
        bundles: &mut [PacketBundle],
        round_compute_unit_price_enabled: bool,
    ) -> ReceiveBundleResults {
        let mut deserialized_bundles = Vec::with_capacity(bundle_count);
        let mut num_dropped_bundles: usize = 0;
        let mut num_dropped_packets: usize = 0;

        for bundle in bundles.iter_mut() {
            match Self::deserialize_bundle(bundle, round_compute_unit_price_enabled) {
                Ok(deserialized_bundle) => {
                    deserialized_bundles.push(deserialized_bundle);
                }
                Err(e) => {
                    saturating_add_assign!(num_dropped_bundles, 1);
                    saturating_add_assign!(num_dropped_packets, bundle.batch.len());
                }
            }
        }

        ReceiveBundleResults {
            deserialized_bundles,
            num_dropped_bundles,
            num_dropped_packets,
        }
    }

    /// Receives bundle packets
    fn receive_until(
        &self,
        recv_timeout: Duration,
        bundle_count_upperbound: usize,
    ) -> Result<(usize, usize, Vec<PacketBundle>), RecvTimeoutError> {
        let start = Instant::now();

        let mut bundles = self.bundle_packet_receiver.recv_timeout(recv_timeout)?;
        let mut num_packets_received = bundles.iter().map(|pb| pb.batch.len()).sum();
        let mut num_bundles_received = bundles.len();

        while let Ok(bundle_packets) = self.bundle_packet_receiver.try_recv() {
            trace!("got more packet batches in bundle packet deserializer");
            num_packets_received += bundle_packets
                .iter()
                .map(|pb| pb.batch.len())
                .sum::<usize>();
            num_bundles_received += bundle_packets.len();

            bundles.extend(bundle_packets);

            if start.elapsed() >= recv_timeout || num_bundles_received >= bundle_count_upperbound {
                break;
            }
        }

        Ok((num_bundles_received, num_packets_received, bundles))
    }

    /// Deserializes the Bundle into DeserializedBundlePackets, returning None if any packet in the
    /// bundle failed to deserialize
    pub fn deserialize_bundle(
        bundle: &mut PacketBundle,
        round_compute_unit_price_enabled: bool,
    ) -> Result<DeserializedBundlePackets, DeserializedBundleError> {
        bundle.batch.iter_mut().for_each(|p| {
            p.meta_mut()
                .set_round_compute_unit_price(round_compute_unit_price_enabled);
        });

        DeserializedBundlePackets::new(bundle, Some(5))
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_perf::packet::to_packet_batches,
        solana_sdk::{
            hash::Hash, pubkey::Pubkey, signature::Keypair, system_transaction,
            transaction::Transaction,
        },
    };

    // fn random_transfer() -> Transaction {
    //     system_transaction::transfer(&Keypair::new(), &Pubkey::new_unique(), 1, Hash::default())
    // }
    //
    // #[test]
    // fn test_deserialize_and_collect_packets_empty() {
    //     let results = PacketDeserializer::deserialize_and_collect_packets(0, &[], false);
    //     assert_eq!(results.deserialized_packets.len(), 0);
    //     assert!(results.new_tracer_stats_option.is_none());
    //     assert_eq!(results.passed_sigverify_count, 0);
    //     assert_eq!(results.failed_sigverify_count, 0);
    // }
    //
    // #[test]
    // fn test_deserialize_and_collect_packets_simple_batches() {
    //     let transactions = vec![random_transfer(), random_transfer()];
    //     let packet_batches = to_packet_batches(&transactions, 1);
    //     assert_eq!(packet_batches.len(), 2);
    //
    //     let packet_count: usize = packet_batches.iter().map(|x| x.len()).sum();
    //     let results = PacketDeserializer::deserialize_and_collect_packets(
    //         packet_count,
    //         &[BankingPacketBatch::new((packet_batches, None))],
    //         false,
    //     );
    //     assert_eq!(results.deserialized_packets.len(), 2);
    //     assert!(results.new_tracer_stats_option.is_none());
    //     assert_eq!(results.passed_sigverify_count, 2);
    //     assert_eq!(results.failed_sigverify_count, 0);
    // }
    //
    // #[test]
    // fn test_deserialize_and_collect_packets_simple_batches_with_failure() {
    //     let transactions = vec![random_transfer(), random_transfer()];
    //     let mut packet_batches = to_packet_batches(&transactions, 1);
    //     assert_eq!(packet_batches.len(), 2);
    //     packet_batches[0][0].meta_mut().set_discard(true);
    //
    //     let packet_count: usize = packet_batches.iter().map(|x| x.len()).sum();
    //     let results = PacketDeserializer::deserialize_and_collect_packets(
    //         packet_count,
    //         &[BankingPacketBatch::new((packet_batches, None))],
    //         false,
    //     );
    //     assert_eq!(results.deserialized_packets.len(), 1);
    //     assert!(results.new_tracer_stats_option.is_none());
    //     assert_eq!(results.passed_sigverify_count, 1);
    //     assert_eq!(results.failed_sigverify_count, 1);
    // }
}
