# Tripwire Sentry

**A NEAR policy-gated MPC signing prototype for EVM transaction digests.**

Tripwire places a verifier approval step before a NEAR contract requests an ECDSA signature from NEAR Chain Signatures.

## Honest scope

Tripwire is a prototype authorization gate. It is **not** a complete transaction simulator, an independent smart-contract auditor, or a guarantee that a transaction is safe.

The current MVP supports:
- EVM legacy (type 0), access-list (type 1), and EIP-1559 (type 2) unsigned transactions in the TypeScript verifier.
- Native-value transfer limits.
- Detection of standard ERC-20 `approve(address,uint256)` calls against a forbidden-spender list.
- Rejection of unlimited ERC-20 approvals by default.
- Rejection of standard ERC-721 `setApprovalForAll` operator approvals.
- A strict `eth,<chain-id>` MPC derivation-path convention.
- Ed25519 verifier verdicts checked by the NEAR contract.
- Verdict binding to a SHA-256 hash of the exact on-chain policy snapshot, preventing a policy update between signing and execution from silently reusing an old verdict.
- NEAR MPC ECDSA signing requests and callback result storage.

Not supported by this MVP:
- EIP-7702/type-4 transactions and delegate authorizations.
- EIP-2612/DAI permit flows or arbitrary token approval methods (known permit selectors are rejected; other unrecognised calldata is not semantically analysed).
- Fork-based transaction simulation.
- Destination-chain broadcasting or execution.
- Independent verification that the off-chain verifier evaluated policy correctly.
- Automatic monitoring of external contract upgrades or exploits.

## Architecture

1. An agent constructs an unsigned EVM transaction and computes its canonical signing digest.
2. The agent submits `payload_hash` and `derivation_path` to `propose_transaction`.
3. The off-chain Sentry receives the exact transaction fields plus the proposal metadata.
4. Sentry reconstructs the unsigned EVM transaction and checks that its Keccak-256 digest equals the on-chain `payload_hash`.
5. Sentry evaluates supported policy rules and signs a verdict using a dedicated Ed25519 key.
6. Sentry signs a message that also includes a SHA-256 hash of the current on-chain policy snapshot. The contract recomputes this hash at execution, so a policy change after signing invalidates the old verdict.
7. The proposing agent calls `execute_with_verdict` with the same nonce, hash, path and signature, attaching exactly 1 yoctoNEAR.
8. The NEAR contract verifies the Ed25519 verdict and requests an ECDSA signature from the configured MPC signer.
9. The callback parses and stores the MPC ECDSA signature components.

MPC signature generation is not the same as broadcasting or executing the EVM transaction.

## Critical configuration

The deployed contract's `get_config` result is the source of truth for:
- `owner_id`
- `verifier_pk`
- `mpc_contract_id`
- `policy`
- `is_paused`

The Sentry service must be configured with a dedicated key whose public key exactly matches `verifier_pk`. Never use the contract administrator's NEAR account key as the Sentry signing key.

### Environment variables

Create `contract/sentry/.env` locally (never commit it):

```env
SENTRY_PRIVATE_KEY=ed25519:YOUR_DEDICATED_SENTRY_SECRET_KEY
SENTRY_EXPECTED_PUBLIC_KEY=ed25519:PUBLIC_KEY_READ_FROM_GET_CONFIG
TRIPWIRE_CONTRACT_ID=v3.tripwire-admin.testnet
NEAR_RPC_URL=[https://rpc.testnet.near.org](https://rpc.testnet.near.org)