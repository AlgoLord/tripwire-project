# Gemini handover — Tripwire final source correction

You are receiving:
1. The user's original `project tripwire zip.zip`.
2. This corrected source patch.

The patch is an engineering correction baseline, not an independent audit and not proof of a live NEAR MPC test.

## Apply these files

Copy the patch files into the original project, preserving the shown relative paths. In particular, replace:
- `contract/src/lib.rs`
- `contract/sentry/verifier.ts`
- `contract/sentry/verifier.test.ts`
- `contract/sentry/e2e_test.ts`
- `contract/sentry/negative_tests.ts`
- `contract/sentry/package.json`
- `contract/sentry/tsconfig.json`
- `contract/sentry/README.md`
- `verifier/src/sentry.ts`
- `verifier/package.json`
- `init.js`
- root `README.md`
- `args.json`
- `contract/args.json`
- `contract/init-args.json`

Add the new `contract/sentry/sentry-cli.ts`, `.env.example`, `docs/testnet-smoke-test.md`, `verifier/tsconfig.json`, `.gitignore`.

Delete stale generated files and regenerate dependency locks:
- Delete `contract/sentry/dist/` (compiled JS is stale and must be rebuilt).
- Delete old `contract/sentry/package-lock.json`.
- Delete old `verifier/package-lock.json`.
- Delete all `node_modules/` and `target/` from the submission archive.
- Run `npm install` in `contract/sentry` and in `verifier` only if you intend to build that compatibility package separately. The canonical Sentry implementation is `contract/sentry/verifier.ts`.

Do not copy any credentials, `.env`, NEAR key files, or local wallet material into the project.

## Important findings from the original ZIP

- Two verifier implementations had different verdict serialization.
- The active `contract/sentry/verifier.ts` used Borsh string length-prefix encoding, while Rust used raw UTF-8 path bytes.
- The alternate `verifier/src/sentry.ts` used the Rust byte layout but lacked sufficient transaction-to-proposal binding and policy validation.
- `contract/sentry/verifier.ts` silently fell back to the contract administrator's NEAR credentials.
- The negative test had a placeholder secret key and was not runnable as a meaningful test.
- The E2E test hardcoded a contract ID and nonce 1.
- `contract/sentry/package.json` had a test command that always failed.
- `init.js`, `args.json`, and `contract/init-args.json` referenced inconsistent contract accounts/public keys.
- The root README was empty.
- The archive contained no frontend, no HTTP API server, and no complete automated live testnet harness. It is currently a contract + verifier library prototype.
- The main ZIP's current `contract/src/lib.rs` has `ProposalRecord.signature: Option<EcdsaSignature>`. The nested `Tripwire-Audit-Package.zip` contains an older Rust snapshot whose `ProposalRecord` does not have that field. These are different persistent-state layouts. The patch follows the main ZIP's current source layout; first establish which layout is deployed before upgrading an initialized account.
- The ZIP did not contain a deployable `.wasm` artifact. Its `target` folder is not proof of a successful current build.

## What the patch changes

- Keeps the current Rust storage struct field order and types unchanged; do not add/remove/reorder state fields without a migration plan.
- Enforces that only the proposing account can execute its proposal.
- Enforces exact `eth,<positive-chain-id>` paths and u64-safe nonce handling.
- Requires exactly 1 yoctoNEAR for the MPC request.
- Uses one canonical verdict format: nonce LE + 32-byte payload hash + raw UTF-8 path + SHA-256 of the current Borsh-compatible on-chain policy snapshot. A policy change after verdict creation invalidates the verdict.
- Removes automatic loading of the admin account key.
- Requires a dedicated Sentry private key and a public key copied from deployed `get_config`, then checks correspondence at startup.
- Reconstructs the canonical unsigned EVM transaction and compares its Keccak digest with the proposal hash before signing.
- Adds policy checks for native value, decoded standard ERC-20 `approve`, blocked spenders, unlimited approvals and standard `setApprovalForAll`.
- Explicitly rejects unsupported EVM transaction types and selected unsupported permit selectors.
- Uses the current documented MPC `request` envelope, `payload_v2.Ecdsa` and `domain_id: 0`.
- Parses the documented MPC response shape (`big_r.affine_point`, `s.scalar`, `recovery_id`) and rejects malformed results.
- Adds owner-only pause, policy-update and verifier-key-rotation methods.
- Makes the Sentry CLI read live `get_config` from NEAR RPC, refuse signing when paused, and use the live on-chain policy instead of a stale local policy file.
- Adds unit tests and a CLI for local verdict generation.

## Required validation — do not skip

### A. TypeScript
From `contract/sentry`:
```bash
npm install
npm run build
npm test
```

If the actual installed `@near-js/crypto` or `ethers` versions have API differences, fix the source and regenerate the lockfile. Do not remove the public-key correspondence check or revert to admin-key fallback just to make tests pass.

### B. Rust
From `contract`:
```bash
cargo check
cargo build --target wasm32-unknown-unknown --release
```
Then use the installed NEAR tooling to build/package WASM. The original source ZIP did not prove that its current Rust source compiles. Do not claim Rust build success until these commands pass.

### C. Live testnet
Use `docs/testnet-smoke-test.md`.
- Read `get_config` from the exact deployed contract.
- Confirm the dedicated Sentry public key matches `verifier_pk`.
- Confirm the contract was deployed from the patched source.
- Test valid and invalid verdicts.
- Test that another account cannot execute a proposal.
- Verify the MPC callback response format on testnet.
- Independently verify the returned ECDSA signature against the derived public key/address and the exact payload hash.

The MPC call schema and callback response must be checked against the current live testnet contract. If actual response JSON differs from the documented schema, save a redacted fixture and adapt the parser. Do not fabricate a callback response or mark mocked tests as live.

## Deployment/state warning

The patch keeps the `TripwireContract` storage fields in the same order and with the same types as the original ZIP, but changing method logic and MPC request format still requires careful deployment validation. Before replacing code on an initialized account:
- do not use the nested `Tripwire-Audit-Package.zip` as the source of truth; it is an older snapshot;
- confirm whether the deployed state was initialized from the main ZIP's `ProposalRecord` layout or the older nested audit package layout;
- if the deployed layout differs, write and test a state migration or deploy a fresh disposable testnet account instead;
- confirm the exact account ID;
- back up/read the existing state/config;
- verify the current deployed contract source/version if possible;
- deploy only after the patched WASM builds;
- test against a disposable testnet deployment first.

The patch adds methods but does not change the state struct layout. Do not initialize an already initialized account again.

## Demo honesty

The original project contains no frontend or API server. A strong deadline-safe demo can be:
1. show the Sentry CLI refusing a transaction whose hash does not match the proposal;
2. show an over-limit or forbidden-spender transaction rejected;
3. show a valid proposal/verdict accepted by the NEAR contract;
4. show the MPC callback and final stored signature if live testnet succeeds.

If live MPC cannot be completed, present the working policy/verdict gate and clearly label MPC callback tests as mocked or incomplete. Do not claim transaction broadcast/execution or full exploit prevention.
