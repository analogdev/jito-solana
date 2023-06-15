use std::collections::hash_map::RandomState;
// use crate::bundle_sanitizer::BundleSanitizerError;
use crate::packet_bundle::PacketBundle;
use solana_perf::sigverify::verify_packet;
use solana_runtime::bank::Bank;
use solana_runtime::transaction_error_metrics::TransactionErrorMetrics;
use solana_sdk::bundle::sanitized::SanitizedBundle;
use solana_sdk::clock::MAX_PROCESSING_AGE;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashSet;
use std::iter::repeat;
use {
    solana_perf::packet::Packet,
    solana_runtime::transaction_priority_details::{
        GetTransactionPriorityDetails, TransactionPriorityDetails,
    },
    solana_sdk::{
        feature_set,
        hash::Hash,
        message::Message,
        sanitize::SanitizeError,
        short_vec::decode_shortu16_len,
        signature::Signature,
        transaction::{
            AddressLoader, SanitizedTransaction, SanitizedVersionedTransaction,
            VersionedTransaction,
        },
    },
    std::{cmp::Ordering, mem::size_of, sync::Arc},
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
        solana_sdk::{signature::Keypair, system_transaction},
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
}
