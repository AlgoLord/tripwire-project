# Remove these stale artifacts when applying the patch

- `contract/sentry/dist/` — compiled JS from the old, inconsistent verifier.
- `contract/sentry/package-lock.json` — regenerate after applying the new package.json.
- `verifier/package-lock.json` — regenerate only if the compatibility package is installed.
- all `node_modules/` folders.
- `contract/target/` and any previously built `.wasm` — rebuild from the patched Rust source.

Do not include `.env`, NEAR credential files, private keys, seed phrases, or local wallet material in the submitted repository.

- `Tripwire-Audit-Package.zip` from the original project — older source snapshot; keep it only as historical evidence, not as the implementation to deploy.
