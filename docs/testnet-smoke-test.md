# Testnet smoke-test checklist

This is a manual testnet procedure. Unit tests do not contact NEAR or the MPC network.

## Before starting

1. Use a disposable NEAR testnet account for the agent.
2. Confirm the exact deployed contract ID. Do not assume `tripwire-admin.testnet` and `v2.tripwire-admin.testnet` are interchangeable.
3. Read `get_config` and record `owner_id`, `verifier_pk`, `mpc_contract_id`, `policy`, and `tx_nonce`.
4. Set `SENTRY_PRIVATE_KEY` to a dedicated verifier key. Set `SENTRY_EXPECTED_PUBLIC_KEY` to the exact `verifier_pk` returned by `get_config`.
5. Run `npm run build` and `npm test` in `contract/sentry`.

## Check contract configuration

```bash
near contract call-function as-read-only "$TRIPWIRE_CONTRACT_ID" get_config json-args '{}' network-config testnet now
```

The public key must match the Sentry key. Do not paste private keys into terminal logs, screenshots, issues, or chat.

## Prepare a transaction proposal

1. Construct an unsigned EVM transaction for a test chain.
2. Use `buildEvmPayloadHash()` from `contract/sentry/verifier.ts` to compute its Keccak-256 signing digest.
3. Select a path exactly matching `eth,<chain-id>`, for example `eth,1` for chain ID 1.
4. Submit the 32-byte digest as a 32-element byte array to `propose_transaction`.
5. Record the returned nonce from the transaction outcome. Do not assume the nonce is `1`.

Example shape (replace all values; JSON array must contain the 32 digest bytes):

```bash
near contract call-function as-transaction "$TRIPWIRE_CONTRACT_ID" propose_transaction \
  json-args '{"payload_hash":[/* 32 decimal byte values */],"derivation_path":"eth,1"}' \
  prepaid-gas 50.0Tgas attached-deposit 0NEAR \
  sign-as "$AGENT_ACCOUNT_ID" network-config testnet sign-with-keychain send
```

## Produce the verdict

Set `TRIPWIRE_CONTRACT_ID`, `SENTRY_PRIVATE_KEY`, and `SENTRY_EXPECTED_PUBLIC_KEY` in the local environment. The CLI reads the live `get_config` response itself.

Pass the exact transaction fields, on-chain nonce, proposal hash and derivation path in `proposal.json`, then run:

```bash
npm run sign:proposal -- proposal.json
```

The verifier must:
- reconstruct the canonical unsigned EVM transaction;
- reproduce the proposal hash exactly;
- read and use the current on-chain policy;
- refuse to sign if the contract is paused;
- confirm the dedicated verifier key's public key matches `get_config`;
- bind the signed verdict to the hash of the current policy snapshot.

If the computed hash differs, stop. Do not sign.

## Execute the verdict

Submit `execute_with_verdict` using:
- the actual proposal nonce;
- the exact same 32-byte hash;
- the exact same derivation path;
- the 64-byte Ed25519 signature as a 64-element decimal byte array;
- exactly `1 yoctoNEAR` attached deposit.

Use enough prepaid gas for the contract method, MPC call and callback. The source currently allocates 150 Tgas to MPC and 30 Tgas to the callback; test with the network's current limits and do not assume a successful receipt merely because the transaction was accepted.

## Verify the outcome

Read `get_proposal(nonce)` and inspect:
- `status`;
- `signature.big_r`;
- `signature.s`;
- `signature.recovery_id`.

Expected final status is `Completed` only if the MPC response was successfully decoded and stored. A failed or malformed MPC response should result in `Failed`.

Independently verify the ECDSA signature against the derived EVM public key/address for the exact transaction digest. Do not call the flow end-to-end verified until this check succeeds.

## Negative checks

Using disposable testnet proposals, verify:
- wrong signature is rejected;
- different hash is rejected;
- different derivation path is rejected;
- another account cannot execute the proposal;
- replaying the same proposal is rejected;
- a proposal while paused is rejected;
- non-owner cannot change policy, verifier key or pause state.

## Evidence to save

Record:
- date/time and network;
- contract account ID;
- `get_config` output (public configuration only);
- deployed WASM hash;
- proposal transaction hash and returned nonce;
- verdict execution transaction hash;
- MPC callback result;
- final `get_proposal` output;
- independent ECDSA verification result.

Never include private keys, seed phrases, or secret environment values in the evidence bundle.


## Optional local CLI

Create `proposal.json` containing the actual on-chain proposal metadata and the exact EVM transaction fields:

```json
{
  "nonce": "1",
  "payloadHashHex": "0xREPLACE_WITH_32_BYTE_HASH",
  "derivationPath": "eth,1",
  "transaction": {
    "type": 2,
    "chainId": 1,
    "nonce": 7,
    "to": "0x0000000000000000000000000000000000000001",
    "value": "1000000000000000",
    "data": "0x",
    "gasLimit": "21000",
    "maxFeePerGas": "30000000000",
    "maxPriorityFeePerGas": "1000000000"
  }
}
```

No local `policy.json` is used. The CLI reads the policy from the deployed contract's `get_config` result and binds its hash into the verdict. This prevents a policy update between verdict generation and execution from silently reusing the old verdict.
