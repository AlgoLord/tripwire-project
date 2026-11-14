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
TRIPWIRE_CONTRACT_ID=v2.tripwire-admin.testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
```

The CLI loads `.env` using `dotenv`. It intentionally refuses to sign if the private key or expected public key is missing, if the key does not match, if the live contract is paused, or if the configured public key differs from `get_config`.

## Install and test Sentry

From `contract/sentry`:

```bash
npm install
npm run build
npm test
```

The unit tests use a generated temporary test key and do not contact NEAR testnet.

## Contract build

From `contract`:

```bash
cargo check
cargo build --target wasm32-unknown-unknown --release
```

The exact NEAR WASM packaging command depends on the installed NEAR CLI / cargo-near version. Build and inspect the generated WASM before deploying.

**Do not claim a successful Rust build or deployment unless the command actually passes in your environment.**

## Contract methods

- `new(verifier_pk, mpc_contract_id, initial_policy)` — initialize once.
- `propose_transaction(payload_hash, derivation_path)` — create a pending proposal.
- `execute_with_verdict(nonce, payload_hash, derivation_path, signature)` — verify the Sentry verdict and request MPC signing; attach exactly 1 yoctoNEAR.
- `mpc_callback(nonce)` — private callback invoked by the contract itself.
- `get_proposal(nonce)` — inspect proposal status and signature result.
- `get_config()` — inspect current configuration.
- `set_paused(paused)` — owner-only emergency pause.
- `set_policy(policy)` — owner-only policy update.
- `set_verifier_pk(verifier_pk)` — owner-only verifier key rotation.

The `policy` is evaluated by the off-chain Sentry service. The contract verifies the Sentry's signature; it does not independently decode the EVM transaction or enforce all policy fields on-chain.

## Verdict message format — keep both sides identical

The current Rust contract and TypeScript verifier use:

```text
u64 nonce (8 bytes, little-endian)
|| payload_hash (32 raw bytes)
|| derivation_path (raw UTF-8 bytes)
|| SHA-256(Borsh-compatible PolicyConfig bytes)
```

The path itself is **not** Borsh string encoding: do not add a four-byte string-length prefix to only one implementation. The policy bytes are encoded in the Rust struct field order: `u128` little-endian, then Borsh `Vec<String>` for `allowed_delegates`, then Borsh `Vec<String>` for `forbidden_spenders`. Both implementations must remain byte-for-byte identical. Changing this format requires changing both Rust and TypeScript together and deploying the matching contract code.

## MPC request and response

The contract uses the current Chain Signatures request shape:

```json
{
  "request": {
    "path": "eth,1",
    "payload_v2": { "Ecdsa": "32-byte-transaction-digest-as-hex" },
    "domain_id": 0
  }
}
```

The callback expects the Secp256k1 response fields:
- `big_r.affine_point` — 33-byte compressed point, hex encoded.
- `s.scalar` — 32-byte scalar, hex encoded.
- `recovery_id` — 0 or 1.

Verify the live testnet contract's actual interface and response before describing the MPC flow as demonstrated. If the response format differs, update the parser based on the observed schema and add a fixture test.

## Security assumptions and limitations

- The Sentry Ed25519 key is trusted. A compromised verifier key can approve malicious proposals.
- The contract checks that only the account that created a proposal can execute it.
- A proposal can only be executed once because its status moves from `Pending` to `SignatureRequested` before the asynchronous MPC call.
- A failed MPC request marks the proposal `Failed`. Create a new proposal to retry.
- The current signed message does not include a domain/version prefix or agent ID. The contract separately enforces proposer identity. A future protocol version should use an explicit versioned/domain-separated message.
- The contract policy is stored on-chain for visibility/configuration, but Sentry performs the actual transaction decoding and policy evaluation.
- Proposal storage consumes NEAR storage. The contract account must have enough NEAR balance to cover state growth.
- The contract owner and deployment keys are custody-critical. Anyone able to replace contract code can change signing policy.
- This prototype has not undergone an independent security audit.

## Testnet smoke test

See [`docs/testnet-smoke-test.md`](docs/testnet-smoke-test.md). Use a disposable test account and a non-sensitive test transaction. Never paste a private key or seed phrase into a public issue, README, chat, or source file.

## Repository layout

```text
contract/
  Cargo.toml
  src/lib.rs
  sentry/
    package.json
    tsconfig.json
    verifier.ts
    verifier.test.ts
    e2e_test.ts
verifier/
  src/sentry.ts   # compatibility re-export; canonical implementation is contract/sentry/verifier.ts
docs/
  testnet-smoke-test.md
```

## Current status

This repository should be treated as a hackathon prototype until the following have been demonstrated with evidence:
- Rust contract compilation and WASM build.
- TypeScript build and unit tests.
- `get_config` matches the Sentry public key.
- A valid verdict is accepted on testnet.
- An invalid verdict is rejected on testnet.
- MPC signing callback returns and stores a valid signature.
- The returned signature is independently verified against the expected derived EVM public key/address.
