// Live testnet flow is intentionally documented in docs/testnet-smoke-test.md.
// Do not auto-submit transactions with a hardcoded account, nonce, or key.
// This file exists as a reminder that unit tests and live MPC E2E tests are separate.
const required = ["TRIPWIRE_CONTRACT_ID", "SENTRY_PRIVATE_KEY", "SENTRY_EXPECTED_PUBLIC_KEY"];
const missing = required.filter((name) => !process.env[name]);
if (missing.length) {
  console.error(`Missing environment variables: ${missing.join(", ")}`);
  console.error("See docs/testnet-smoke-test.md for the manual testnet procedure.");
  process.exitCode = 1;
} else {
  console.log("Sentry environment variables are present.");
  console.log("This preflight does not prove key correspondence or live MPC signing.");
  console.log("Run npm test, verify get_config, then follow docs/testnet-smoke-test.md.");
}
