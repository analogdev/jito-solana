// use crate::bundle_sanitizer::BundleSanitizerError;
use crate::packet_bundle::PacketBundle;
use {
    solana_perf::{packet::Packet, sigverify::verify_packet},
    solana_runtime::{
        bank::Bank,
        transaction_error_metrics::TransactionErrorMetrics,
        transaction_priority_details::{GetTransactionPriorityDetails, TransactionPriorityDetails},
    },
    solana_sdk::{
        bundle::sanitized::SanitizedBundle,
        clock::MAX_PROCESSING_AGE,
        feature_set,
        hash::Hash,
        message::Message,
        pubkey::Pubkey,
        sanitize::SanitizeError,
        short_vec::decode_shortu16_len,
        signature::Signature,
        transaction::{
            AddressLoader, SanitizedTransaction, SanitizedVersionedTransaction,
            VersionedTransaction,
        },
    },
    std::{
        cmp::Ordering,
        collections::{hash_map::RandomState, HashSet},
        iter::repeat,
        mem::size_of,
        sync::Arc,
    },
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum DeserializedPacketError {
    #[error("ShortVec Failed to Deserialize")]
    // short_vec::decode_shortu16_len() currently returns () on error
    ShortVecError(()),
    #[error("Deserialization Error: {0}")]
    DeserializationError(#[from] bincode::Error),
    #[error("overflowed on signature size {0}")]
    SignatureOverflowed(usize),
    #[error("packet failed sanitization {0}")]
    SanitizeError(#[from] SanitizeError),
    #[error("transaction failed prioritization")]
    PrioritizationFailure,
    #[error("vote transaction failure")]
    VoteTransactionError,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ImmutableDeserializedPacket {
    original_packet: Packet,
    transaction: SanitizedVersionedTransaction,
    message_hash: Hash,
    is_simple_vote: bool,
    priority_details: TransactionPriorityDetails,
}

impl ImmutableDeserializedPacket {
    pub fn new(packet: Packet) -> Result<Self, DeserializedPacketError> {
        let versioned_transaction: VersionedTransaction = packet.deserialize_slice(..)?;
        let sanitized_transaction = SanitizedVersionedTransaction::try_from(versioned_transaction)?;
        let message_bytes = packet_message(&packet)?;
        let message_hash = Message::hash_raw_message(message_bytes);
        let is_simple_vote = packet.meta().is_simple_vote_tx();

        // drop transaction if prioritization fails.
        let mut priority_details = sanitized_transaction
            .get_transaction_priority_details(packet.meta().round_compute_unit_price())
            .ok_or(DeserializedPacketError::PrioritizationFailure)?;

        // set priority to zero for vote transactions
        if is_simple_vote {
            priority_details.priority = 0;
        };

        Ok(Self {
            original_packet: packet,
            transaction: sanitized_transaction,
            message_hash,
            is_simple_vote,
            priority_details,
        })
    }

    pub fn original_packet(&self) -> &Packet {
        &self.original_packet
    }

    pub fn transaction(&self) -> &SanitizedVersionedTransaction {
        &self.transaction
    }

    pub fn message_hash(&self) -> &Hash {
        &self.message_hash
    }

    pub fn is_simple_vote(&self) -> bool {
        self.is_simple_vote
    }

    pub fn priority(&self) -> u64 {
        self.priority_details.priority
    }

    pub fn compute_unit_limit(&self) -> u64 {
        self.priority_details.compute_unit_limit
    }

    // This function deserializes packets into transactions, computes the blake3 hash of transaction
    // messages, and verifies secp256k1 instructions.
    pub fn build_sanitized_transaction(
        &self,
        feature_set: &Arc<feature_set::FeatureSet>,
        votes_only: bool,
        address_loader: impl AddressLoader,
    ) -> Option<SanitizedTransaction> {
        if votes_only && !self.is_simple_vote() {
            return None;
        }
        let tx = SanitizedTransaction::try_new(
            self.transaction().clone(),
            *self.message_hash(),
            self.is_simple_vote(),
            address_loader,
        )
        .ok()?;
        tx.verify_precompiles(feature_set).ok()?;
        Some(tx)
    }
}

impl PartialOrd for ImmutableDeserializedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ImmutableDeserializedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority().cmp(&other.priority())
    }
}

/// Read the transaction message from packet data
fn packet_message(packet: &Packet) -> Result<&[u8], DeserializedPacketError> {
    let (sig_len, sig_size) = packet
        .data(..)
        .and_then(|bytes| decode_shortu16_len(bytes).ok())
        .ok_or(DeserializedPacketError::ShortVecError(()))?;
    sig_len
        .checked_mul(size_of::<Signature>())
        .and_then(|v| v.checked_add(sig_size))
        .and_then(|msg_start| packet.data(msg_start..))
        .ok_or(DeserializedPacketError::SignatureOverflowed(sig_size))
}

#[derive(Debug, Error)]
pub enum DeserializedBundleError {
    #[error("FailedToSerializePacket")]
    FailedToSerializePacket,

    #[error("EmptyBatch")]
    EmptyBatch,

    #[error("TooManyPackets")]
    TooManyPackets,

    #[error("MarkedDiscard")]
    MarkedDiscard,

    #[error("SignatureVerificationFailure")]
    SignatureVerificationFailure,

    #[error("Bank is in vote-only mode")]
    VoteOnlyMode,

    #[error("Bundle packet batch failed pre-check")]
    FailedPacketBatchPreCheck,

    #[error("Bundle mentions blacklisted account")]
    BlacklistedAccount,

    #[error("Bundle contains a transaction that failed to serialize")]
    FailedToSerializeTransaction,

    #[error("Bundle contains a duplicate transaction")]
    DuplicateTransaction,

    #[error("Bundle failed check_transactions")]
    FailedCheckTransactions,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeserializedBundlePackets {
    uuid: String,
    packets: Vec<ImmutableDeserializedPacket>,
}

impl DeserializedBundlePackets {
    pub fn new(
        bundle: &mut PacketBundle,
        max_len: Option<usize>,
    ) -> Result<Self, DeserializedBundleError> {
        // Checks: non-zero, less than some length, marked for discard, signature verification failed, failed to sanitize to
        // ImmutableDeserializedPacket
        if bundle.batch.is_empty() {
            return Err(DeserializedBundleError::EmptyBatch);
        }
        if max_len
            .map(|max_len| bundle.batch.len() > max_len)
            .unwrap_or(false)
        {
            return Err(DeserializedBundleError::TooManyPackets);
        }
        if bundle.batch.iter().any(|p| p.meta().discard()) {
            return Err(DeserializedBundleError::MarkedDiscard);
        }
        if bundle.batch.iter_mut().any(|p| !verify_packet(p, false)) {
            return Err(DeserializedBundleError::SignatureVerificationFailure);
        }

        let immutable_packets: Vec<_> = bundle
            .batch
            .iter()
            .filter_map(|p| ImmutableDeserializedPacket::new(p.clone()).ok())
            .collect();

        if bundle.batch.len() != immutable_packets.len() {
            return Err(DeserializedBundleError::FailedToSerializePacket);
        }

        Ok(Self {
            uuid: bundle.bundle_id.clone(),
            packets: immutable_packets,
        })
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// A bundle has the following requirements:
    /// - all transactions must be sanitiz-able
    /// - no duplicate signatures
    /// - must not contain a blacklisted account
    /// - can't already be processed or contain a bad blockhash
    pub fn build_sanitized_bundle(
        &self,
        bank: &Bank,
        blacklisted_accounts: &HashSet<Pubkey>,
        transaction_error_metrics: &mut TransactionErrorMetrics,
    ) -> Result<SanitizedBundle, DeserializedBundleError> {
        let transactions: Vec<SanitizedTransaction> = self
            .packets
            .iter()
            .filter_map(|p| {
                p.build_sanitized_transaction(&bank.feature_set, bank.vote_only_bank(), bank)
            })
            .collect();

        if self.packets.len() != transactions.len() {
            return Err(DeserializedBundleError::FailedToSerializeTransaction);
        }

        let unique_signatures: HashSet<&Signature, RandomState> =
            HashSet::from_iter(transactions.iter().map(|tx| tx.signature()));
        if unique_signatures.len() != transactions.len() {
            return Err(DeserializedBundleError::DuplicateTransaction);
        }

        let contains_blacklisted_account = transactions.iter().any(|tx| {
            tx.message()
                .account_keys()
                .iter()
                .any(|acc| blacklisted_accounts.contains(acc))
        });

        if contains_blacklisted_account {
            return Err(DeserializedBundleError::BlacklistedAccount);
        }

        // assume everything locks okay to check for already-processed transaction or expired/invalid blockhash
        let lock_results: Vec<_> = repeat(Ok(())).take(transactions.len()).collect();
        let check_results = bank.check_transactions(
            &transactions,
            &lock_results,
            MAX_PROCESSING_AGE,
            transaction_error_metrics,
        );

        if check_results.iter().any(|r| r.0.is_err()) {
            return Err(DeserializedBundleError::FailedCheckTransactions);
        }

        Ok(SanitizedBundle {
            transactions,
            bundle_id: self.uuid.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            bundle_sanitizer::{get_sanitized_bundle, MAX_PACKETS_PER_BUNDLE},
            packet_bundle::PacketBundle,
            tip_manager::{TipDistributionAccountConfig, TipManager, TipManagerConfig},
        },
        solana_address_lookup_table_program::instruction::create_lookup_table,
        solana_ledger::genesis_utils::create_genesis_config,
        solana_perf::packet::PacketBatch,
        solana_runtime::{
            bank::Bank, genesis_utils::GenesisConfigInfo,
            transaction_error_metrics::TransactionErrorMetrics,
        },
        solana_sdk::{
            bundle::sanitized::derive_bundle_id,
            hash::Hash,
            instruction::Instruction,
            packet::Packet,
            pubkey::Pubkey,
            signature::{Keypair, Signer},
            system_transaction::transfer,
            transaction::{Transaction, VersionedTransaction},
        },
        solana_sdk::{signature::Keypair, system_transaction},
        std::{collections::HashSet, sync::Arc},
    };

    #[test]
    fn simple_deserialized_packet() {
        let tx = system_transaction::transfer(
            &Keypair::new(),
            &solana_sdk::pubkey::new_rand(),
            1,
            Hash::new_unique(),
        );
        let packet = Packet::from_data(None, tx).unwrap();
        let deserialized_packet = ImmutableDeserializedPacket::new(packet);

        assert!(matches!(deserialized_packet, Ok(_)));
    }
    // #[test]
    // fn test_simple_get_sanitized_bundle() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let tx = VersionedTransaction::from(transfer(
    //         &mint_keypair,
    //         &kp.pubkey(),
    //         1,
    //         genesis_config.hash(),
    //     ));
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let tx_signature = tx.signatures[0];
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id,
    //     };
    //
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     let sanitized_bundle = get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors,
    //     )
    //         .unwrap();
    //     assert_eq!(sanitized_bundle.transactions.len(), 1);
    //     assert_eq!(sanitized_bundle.transactions[0].signature(), &tx_signature);
    // }
    //
    // #[test]
    // fn test_fail_to_sanitize_consensus_account() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let tx = VersionedTransaction::from(transfer(
    //         &mint_keypair,
    //         &kp.pubkey(),
    //         1,
    //         genesis_config.hash(),
    //     ));
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id,
    //     };
    //
    //     let consensus_accounts_cache = HashSet::from([kp.pubkey()]);
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &consensus_accounts_cache,
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fail_to_sanitize_duplicate_transaction() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let tx = VersionedTransaction::from(transfer(
    //         &mint_keypair,
    //         &kp.pubkey(),
    //         1,
    //         genesis_config.hash(),
    //     ));
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     // bundle with a duplicate transaction
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet.clone(), packet]),
    //         bundle_id,
    //     };
    //
    //     // fails to pop because bundle it locks the same transaction twice
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_bad_blockhash() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let tx =
    //         VersionedTransaction::from(transfer(&mint_keypair, &kp.pubkey(), 1, Hash::default()));
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet.clone(), packet]),
    //         bundle_id,
    //     };
    //
    //     // fails to pop because bundle has bad blockhash
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_already_processed() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let tx = VersionedTransaction::from(transfer(
    //         &mint_keypair,
    //         &kp.pubkey(),
    //         1,
    //         genesis_config.hash(),
    //     ));
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet.clone()]),
    //         bundle_id: bundle_id.clone(),
    //     };
    //
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     let sanitized_bundle = get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors,
    //     )
    //         .unwrap();
    //
    //     let results = bank.process_entry_transactions(
    //         sanitized_bundle
    //             .transactions
    //             .into_iter()
    //             .map(|tx| tx.to_versioned_transaction())
    //             .collect(),
    //     );
    //     assert_eq!(results.len(), 1);
    //     assert_eq!(results[0], Ok(()));
    //
    //     // try to process the same one again shall fail
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id,
    //     };
    //
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_bundle_tip_program() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo { genesis_config, .. } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let tip_manager = TipManager::new(TipManagerConfig {
    //         tip_payment_program_id: Pubkey::new_unique(),
    //         tip_distribution_program_id: Pubkey::new_unique(),
    //         tip_distribution_account_config: TipDistributionAccountConfig {
    //             merkle_root_upload_authority: Pubkey::new_unique(),
    //             vote_account: Pubkey::new_unique(),
    //             commission_bps: 0,
    //         },
    //     });
    //
    //     let kp = Keypair::new();
    //     let tx = VersionedTransaction::from(Transaction::new_signed_with_payer(
    //         &[Instruction::new_with_bytes(
    //             tip_manager.tip_payment_program_id(),
    //             &[0],
    //             vec![],
    //         )],
    //         Some(&kp.pubkey()),
    //         &[&kp],
    //         genesis_config.hash(),
    //     ));
    //     tx.sanitize(false).unwrap();
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id,
    //     };
    //
    //     // fails to pop because bundle mentions tip program
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::from_iter([tip_manager.tip_payment_program_id()]),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_txv2_sanitized_bundle_ok() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo { genesis_config, .. } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //     let tx = VersionedTransaction::from(Transaction::new_signed_with_payer(
    //         &[create_lookup_table(kp.pubkey(), kp.pubkey(), bank.slot()).0],
    //         Some(&kp.pubkey()),
    //         &[&kp],
    //         genesis_config.hash(),
    //     ));
    //     tx.sanitize(false).unwrap();
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //     let bundle_id = derive_bundle_id(&vec![tx]);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id,
    //     };
    //
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_ok());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_empty_bundle() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo { genesis_config, .. } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![]),
    //         bundle_id: String::default(),
    //     };
    //     // fails to pop because empty bundle
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_too_many_packets() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let txs = (0..MAX_PACKETS_PER_BUNDLE + 1)
    //         .map(|i| {
    //             VersionedTransaction::from(transfer(
    //                 &mint_keypair,
    //                 &kp.pubkey(),
    //                 i as u64,
    //                 genesis_config.hash(),
    //             ))
    //         })
    //         .collect::<Vec<_>>();
    //     let packets = txs.iter().map(|tx| Packet::from_data(None, tx).unwrap());
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(packets.collect()),
    //         bundle_id: derive_bundle_id(&txs),
    //     };
    //     // fails to pop because too many packets in a bundle
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_discarded() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let tx = VersionedTransaction::from(transfer(
    //         &mint_keypair,
    //         &kp.pubkey(),
    //         1,
    //         genesis_config.hash(),
    //     ));
    //     let mut packet = Packet::from_data(None, &tx).unwrap();
    //     packet.meta_mut().set_discard(true);
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id: derive_bundle_id(&vec![tx]),
    //     };
    //
    //     // fails to pop because one of the packets is marked as discard
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_fails_to_sanitize_bad_sigverify() {
    //     solana_logger::setup();
    //     let GenesisConfigInfo {
    //         genesis_config,
    //         mint_keypair,
    //         ..
    //     } = create_genesis_config(2);
    //     let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
    //
    //     let kp = Keypair::new();
    //
    //     let mut tx = VersionedTransaction::from(transfer(
    //         &mint_keypair,
    //         &kp.pubkey(),
    //         1,
    //         genesis_config.hash(),
    //     ));
    //
    //     let _ = tx.signatures.pop();
    //
    //     let bad_kp = Keypair::new();
    //     let serialized = tx.message.serialize();
    //     let bad_sig = bad_kp.sign_message(&serialized);
    //     tx.signatures.push(bad_sig);
    //
    //     let packet = Packet::from_data(None, &tx).unwrap();
    //
    //     let packet_bundle = PacketBundle {
    //         batch: PacketBatch::new(vec![packet]),
    //         bundle_id: derive_bundle_id(&vec![tx]),
    //     };
    //     let mut transaction_errors = TransactionErrorMetrics::default();
    //     assert!(get_sanitized_bundle(
    //         &packet_bundle,
    //         &bank,
    //         &HashSet::default(),
    //         &HashSet::default(),
    //         &mut transaction_errors
    //     )
    //         .is_err());
    // }
}
