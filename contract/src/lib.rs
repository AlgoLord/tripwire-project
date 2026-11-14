use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{UnorderedMap, UnorderedSet};
use near_sdk::{
    env, near, AccountId, BorshStorageKey, Gas, NearToken, Promise, PromiseResult, PublicKey,
};

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
#[borsh(crate = "near_sdk::borsh")]
pub struct PolicyConfig {
    pub max_eth_transfer: near_sdk::json_types::U128,
    pub allowed_delegates: Vec<String>,
    pub forbidden_spenders: Vec<String>,
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, PartialEq, Debug,
)]
#[serde(crate = "near_sdk::serde")]
#[borsh(crate = "near_sdk::borsh")]
pub enum ProposalStatus {
    Pending,
    Approved,
    SignatureRequested,
    Completed,
    Failed,
    Rejected,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
#[borsh(crate = "near_sdk::borsh")]
pub struct EcdsaSignature {
    /// Compressed SEC1 point from MPC (33 bytes).
    pub big_r: Vec<u8>,
    /// ECDSA scalar s (32 bytes).
    pub s: Vec<u8>,
    /// Recovery parity (0 or 1).
    pub recovery_id: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
#[borsh(crate = "near_sdk::borsh")]
pub struct ProposalRecord {
    pub nonce: u64,
    pub agent_id: AccountId,
    pub payload_hash: [u8; 32],
    pub derivation_path: String,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub signature: Option<EcdsaSignature>,
}

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    ConsumedHashes,
    AuditRecords,
    Proposals,
}

#[near(contract_state)]
pub struct TripwireContract {
    pub owner_id: AccountId,
    pub verifier_pk: PublicKey,
    pub mpc_contract_id: AccountId,
    pub is_paused: bool,
    pub policy: PolicyConfig,
    pub tx_nonce: u64,
    // Retained to preserve the existing state layout. Proposal status/nonce is the
    // authoritative replay guard in this MVP; this set is not currently consulted.
    pub consumed_hashes: UnorderedSet<Vec<u8>>,
    pub audit_records: UnorderedMap<u64, ProposalRecord>,
    pub proposals: UnorderedMap<u64, ProposalRecord>,
}

impl Default for TripwireContract {
    fn default() -> Self {
        env::panic_str("Tripwire contract is not initialized");
    }
}

/// Current NEAR MPC Chain Signatures ECDSA response shape:
/// { "scheme":"Secp256k1",
///   "big_r":{"affine_point":"<hex>"},
///   "s":{"scalar":"<hex>"},
///   "recovery_id":0 }
fn parse_mpc_ecdsa_result(bytes: &[u8]) -> Result<EcdsaSignature, String> {
    let value: near_sdk::serde_json::Value =
        near_sdk::serde_json::from_slice(bytes).map_err(|e| format!("Invalid MPC JSON: {e}"))?;

    if let Some(scheme) = value.get("scheme").and_then(|v| v.as_str()) {
        if scheme != "Secp256k1" {
            return Err(format!("Expected Secp256k1 MPC result, received {scheme}"));
        }
    }

    let big_r_hex = value
        .get("big_r")
        .and_then(|v| v.get("affine_point"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "MPC result missing big_r.affine_point".to_string())?;

    let s_hex = value
        .get("s")
        .and_then(|v| v.get("scalar"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "MPC result missing s.scalar".to_string())?;

    let recovery_id = value
        .get("recovery_id")
        .and_then(|v| v.as_u64())
        .and_then(|v| u8::try_from(v).ok())
        .filter(|v| *v <= 1)
        .ok_or_else(|| "MPC result has invalid recovery_id".to_string())?;

    let big_r_hex = big_r_hex.strip_prefix("0x").unwrap_or(big_r_hex);
    let s_hex = s_hex.strip_prefix("0x").unwrap_or(s_hex);
    let big_r = hex::decode(big_r_hex).map_err(|e| format!("Invalid big_r hex: {e}"))?;
    let s = hex::decode(s_hex).map_err(|e| format!("Invalid s hex: {e}"))?;

    if big_r.len() != 33 {
        return Err(format!("Expected 33-byte compressed big_r, received {}", big_r.len()));
    }
    if s.len() != 32 {
        return Err(format!("Expected 32-byte s scalar, received {}", s.len()));
    }

    Ok(EcdsaSignature {
        big_r,
        s,
        recovery_id,
    })
}

fn serialize_policy(policy: &PolicyConfig) -> Vec<u8> {
    let mut bytes = Vec::new();
    // Borsh-compatible encoding for the fields in PolicyConfig:
    // u128 LE, Vec<String>, Vec<String>.
    bytes.extend_from_slice(&policy.max_eth_transfer.0.to_le_bytes());

    let allowed_len: u32 = policy
        .allowed_delegates
        .len()
        .try_into()
        .expect("Too many allowed delegates");
    bytes.extend_from_slice(&allowed_len.to_le_bytes());
    for value in &policy.allowed_delegates {
        let value_bytes = value.as_bytes();
        let len: u32 = value_bytes.len().try_into().expect("Delegate string too long");
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(value_bytes);
    }

    let forbidden_len: u32 = policy
        .forbidden_spenders
        .len()
        .try_into()
        .expect("Too many forbidden spenders");
    bytes.extend_from_slice(&forbidden_len.to_le_bytes());
    for value in &policy.forbidden_spenders {
        let value_bytes = value.as_bytes();
        let len: u32 = value_bytes.len().try_into().expect("Spender string too long");
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(value_bytes);
    }
    bytes
}

fn serialize_verdict_message(
    nonce: u64,
    payload_hash: &[u8; 32],
    derivation_path: &str,
    policy_hash: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + 32 + derivation_path.len() + 32);
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(payload_hash);
    message.extend_from_slice(derivation_path.as_bytes());
    message.extend_from_slice(policy_hash);
    message
}

fn validate_eth_derivation_path(path: &str) {
    // MVP path convention: eth,<positive EVM chain id>, e.g. eth,1 or eth,8453.
    // Keep this exact in the TypeScript verifier.
    let chain_id = path
        .strip_prefix("eth,")
        .expect("Tripwire Error: derivation path must start with eth,");
    assert!(
        !chain_id.is_empty()
            && chain_id.len() <= 20
            && chain_id.bytes().all(|b| b.is_ascii_digit())
            && chain_id.as_bytes()[0] != b'0',
        "Tripwire Error: derivation path must be eth,<positive-chain-id>"
    );
    let parsed = chain_id
        .parse::<u64>()
        .expect("Tripwire Error: invalid EVM chain id in derivation path");
    assert!(parsed > 0, "Tripwire Error: chain id must be positive");
}

#[near]
impl TripwireContract {
    #[init]
    pub fn new(
        verifier_pk: String,
        mpc_contract_id: AccountId,
        initial_policy: PolicyConfig,
    ) -> Self {
        let verifier_pk: PublicKey = verifier_pk
            .parse()
            .expect("Tripwire Error: Invalid verifier public key format");
        let pk_bytes = verifier_pk.as_bytes();
        let raw_pk = if pk_bytes.len() == 33 {
            &pk_bytes[1..]
        } else {
            pk_bytes
        };
        assert_eq!(
            raw_pk.len(),
            32,
            "Tripwire Error: Verifier public key must be 32-byte Ed25519"
        );

        Self {
            owner_id: env::predecessor_account_id(),
            verifier_pk,
            mpc_contract_id,
            is_paused: false,
            policy: initial_policy,
            tx_nonce: 0,
            consumed_hashes: UnorderedSet::new(StorageKey::ConsumedHashes),
            audit_records: UnorderedMap::new(StorageKey::AuditRecords),
            proposals: UnorderedMap::new(StorageKey::Proposals),
        }
    }

    /// Submit a transaction hash for policy review. The off-chain verifier must
    /// derive this hash from the actual unsigned EVM transaction before approving it.
    pub fn propose_transaction(&mut self, payload_hash: [u8; 32], derivation_path: String) -> u64 {
        assert!(!self.is_paused, "Tripwire Error: Contract is paused");
        validate_eth_derivation_path(&derivation_path);

        self.tx_nonce = self
            .tx_nonce
            .checked_add(1)
            .expect("Tripwire Error: nonce overflow");
        let nonce = self.tx_nonce;
        let agent_id = env::predecessor_account_id();

        let proposal = ProposalRecord {
            nonce,
            agent_id: agent_id.clone(),
            payload_hash,
            derivation_path,
            status: ProposalStatus::Pending,
            created_at: env::block_timestamp(),
            signature: None,
        };

        self.proposals.insert(nonce, proposal);
        env::log_str(&format!(
            "Tripwire Proposal Created: nonce={}, agent={}",
            nonce, agent_id
        ));
        nonce
    }

    /// Verify a Sentry verdict, then request the ECDSA signature from NEAR MPC.
    ///
    /// Verdict bytes: nonce LE (8 bytes) || payload_hash (32 bytes) ||
    /// raw UTF-8 path || SHA-256(Borsh-compatible current policy bytes).
    /// Do not add a Borsh string prefix to the path on only one side.
    #[payable]
    pub fn execute_with_verdict(
        &mut self,
        nonce: u64,
        payload_hash: [u8; 32],
        derivation_path: String,
        signature: Vec<u8>,
    ) -> Promise {
        assert!(!self.is_paused, "Tripwire Error: Contract is paused");
        assert_eq!(
            env::attached_deposit(),
            NearToken::from_yoctonear(1),
            "Tripwire Error: Attach exactly 1 yoctoNEAR"
        );
        validate_eth_derivation_path(&derivation_path);

        let mut proposal = self
            .proposals
            .get(&nonce)
            .expect("Tripwire Error: Proposal does not exist")
            .clone();

        assert_eq!(
            proposal.status,
            ProposalStatus::Pending,
            "Tripwire Error: Proposal is not pending (replay or invalid state)"
        );
        assert_eq!(
            env::predecessor_account_id(),
            proposal.agent_id,
            "Tripwire Error: Only the proposing agent may execute this proposal"
        );
        assert_eq!(
            proposal.payload_hash, payload_hash,
            "Tripwire Error: Payload hash mismatch"
        );
        assert_eq!(
            proposal.derivation_path, derivation_path,
            "Tripwire Error: Derivation path mismatch"
        );

        let sig_array: &[u8; 64] = signature
            .as_slice()
            .try_into()
            .expect("Tripwire Error: Ed25519 signature must be exactly 64 bytes");

        let pk_bytes = self.verifier_pk.as_bytes();
        let raw_pk = if pk_bytes.len() == 33 {
            &pk_bytes[1..]
        } else {
            pk_bytes
        };
        let pk_array: &[u8; 32] = raw_pk
            .try_into()
            .expect("Tripwire Error: verifier key must be 32 bytes");

        // Bind the verdict to the exact on-chain policy snapshot. If the owner
        // changes policy after Sentry signs, verification fails and the proposal
        // must be re-evaluated under the new policy.
        let policy_hash = env::sha256_array(&serialize_policy(&self.policy));
        let message = serialize_verdict_message(
            nonce,
            &payload_hash,
            &derivation_path,
            &policy_hash,
        );

        assert!(
            env::ed25519_verify(sig_array, &message, pk_array),
            "Tripwire Error: Invalid verifier verdict signature"
        );

        // Mark consumed before the asynchronous external call. A failed MPC call
        // is terminal for this proposal; a new proposal must be created to retry.
        proposal.status = ProposalStatus::SignatureRequested;
        self.proposals.insert(nonce, proposal.clone());
        self.audit_records.insert(nonce, proposal);

        // Current MPC request wire format. `payload_v2.Ecdsa` is the 32-byte
        // transaction digest encoded as hex; domain_id 0 is Secp256k1.
        let mpc_args = near_sdk::serde_json::json!({
            "request": {
                "path": derivation_path,
                "payload_v2": {
                    "Ecdsa": hex::encode(payload_hash)
                },
                "domain_id": 0
            }
        });

        let sign_promise = Promise::new(self.mpc_contract_id.clone()).function_call(
            "sign".to_string(),
            mpc_args.to_string().into_bytes(),
            NearToken::from_yoctonear(1),
            Gas::from_tgas(150),
        );

        sign_promise.then(
            Promise::new(env::current_account_id()).function_call(
                "mpc_callback".to_string(),
                near_sdk::serde_json::json!({ "nonce": nonce })
                    .to_string()
                    .into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(30),
            ),
        )
    }

    /// Only the contract itself may invoke this callback.
    #[private]
    pub fn mpc_callback(&mut self, nonce: u64) -> bool {
        let mut proposal = self
            .proposals
            .get(&nonce)
            .expect("Tripwire Error: Proposal not found")
            .clone();

        assert_eq!(
            proposal.status,
            ProposalStatus::SignatureRequested,
            "Tripwire Error: Callback for proposal not awaiting MPC"
        );

        let outcome = match env::promise_result(0) {
            PromiseResult::Successful(bytes) => match parse_mpc_ecdsa_result(&bytes) {
                Ok(signature) => {
                    proposal.signature = Some(signature);
                    proposal.status = ProposalStatus::Completed;
                    true
                }
                Err(error) => {
                    env::log_str(&format!("Tripwire MPC response rejected: {}", error));
                    proposal.status = ProposalStatus::Failed;
                    false
                }
            },
            PromiseResult::Failed => {
                proposal.status = ProposalStatus::Failed;
                false
            }
        };

        self.proposals.insert(nonce, proposal.clone());
        self.audit_records.insert(nonce, proposal);
        outcome
    }

    /// Public audit view. MPC signatures are public cryptographic outputs, not keys.
    pub fn get_proposal(&self, nonce: u64) -> Option<ProposalRecord> {
        self.proposals.get(&nonce).cloned()
    }

    pub fn get_config(&self) -> near_sdk::serde_json::Value {
        near_sdk::serde_json::json!({
            "owner_id": self.owner_id,
            "verifier_pk": self.verifier_pk,
            "mpc_contract_id": self.mpc_contract_id,
            "is_paused": self.is_paused,
            "policy": self.policy,
            "tx_nonce": self.tx_nonce
        })
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.is_paused = paused;
    }

    pub fn set_policy(&mut self, policy: PolicyConfig) {
        self.assert_owner();
        self.policy = policy;
    }

    pub fn set_verifier_pk(&mut self, verifier_pk: String) {
        self.assert_owner();
        let parsed: PublicKey = verifier_pk
            .parse()
            .expect("Tripwire Error: Invalid verifier public key format");
        let bytes = parsed.as_bytes();
        let raw = if bytes.len() == 33 { &bytes[1..] } else { bytes };
        assert_eq!(raw.len(), 32, "Tripwire Error: Expected Ed25519 public key");
        self.verifier_pk = parsed;
    }

    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Tripwire Error: Only owner may perform this action"
        );
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_message_uses_raw_utf8_path_without_borsh_prefix() {
        let hash = [0x11u8; 32];
        let policy_hash = [0x22u8; 32];
        let message = serialize_verdict_message(1, &hash, "eth,1", &policy_hash);

        assert_eq!(&message[..8], &1u64.to_le_bytes());
        assert_eq!(&message[8..40], &hash);
        assert_eq!(&message[40..45], b"eth,1");
        assert_eq!(&message[45..], &policy_hash);
        assert_eq!(message.len(), 77);
    }

    #[test]
    fn accepts_only_exact_eth_chain_path() {
        validate_eth_derivation_path("eth,1");
        validate_eth_derivation_path("eth,8453");
    }

    #[test]
    #[should_panic]
    fn rejects_path_with_suffix() {
        validate_eth_derivation_path("eth,1,extra");
    }

    #[test]
    #[should_panic]
    fn rejects_zero_chain_id() {
        validate_eth_derivation_path("eth,0");
    }

    #[test]
    fn policy_serialization_matches_borsh_field_order() {
        let policy = PolicyConfig {
            max_eth_transfer: near_sdk::json_types::U128(1),
            allowed_delegates: vec!["abc".to_string()],
            forbidden_spenders: vec!["0x01".to_string()],
        };
        let bytes = serialize_policy(&policy);
        assert_eq!(&bytes[..16], &1u128.to_le_bytes());
        assert_eq!(&bytes[16..20], &1u32.to_le_bytes());
        assert_eq!(&bytes[20..24], &3u32.to_le_bytes());
        assert_eq!(&bytes[24..27], b"abc");
        assert_eq!(&bytes[27..31], &1u32.to_le_bytes());
        assert_eq!(&bytes[31..35], &4u32.to_le_bytes());
        assert_eq!(&bytes[35..39], b"0x01");
        assert_eq!(
            hex::encode(&bytes),
            "010000000000000000000000000000000100000003000000616263010000000400000030783031"
        );
    }

    #[test]
    fn parses_current_mpc_ecdsa_response_shape() {
        let json = br#"{
            "scheme":"Secp256k1",
            "big_r":{"affine_point":"020000000000000000000000000000000000000000000000000000000000000000"},
            "s":{"scalar":"0000000000000000000000000000000000000000000000000000000000000001"},
            "recovery_id":0
        }"#;
        let parsed = parse_mpc_ecdsa_result(json).expect("valid MPC result");
        assert_eq!(parsed.big_r.len(), 33);
        assert_eq!(parsed.s.len(), 32);
        assert_eq!(parsed.recovery_id, 0);
    }
}
