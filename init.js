// Initialization-argument generator only. It does NOT deploy or initialize the contract.
// Run this only for a NEW, uninitialized contract account.
const fs = require("node:fs");
const path = require("node:path");

const contractId = process.env.TRIPWIRE_CONTRACT_ID;
const verifierPublicKey = process.env.SENTRY_EXPECTED_PUBLIC_KEY;
const mpcContractId = process.env.MPC_CONTRACT_ID || "v1.signer-prod.testnet";

if (!contractId) {
  throw new Error("Set TRIPWIRE_CONTRACT_ID to the exact account that will own the Tripwire contract.");
}
if (!verifierPublicKey || !verifierPublicKey.startsWith("ed25519:")) {
  throw new Error("Set SENTRY_EXPECTED_PUBLIC_KEY to the dedicated Sentry public key (not an admin key).");
}

const args = {
  verifier_pk: verifierPublicKey,
  mpc_contract_id: mpcContractId,
  initial_policy: {
    max_eth_transfer: "1000000000000000000",
    allowed_delegates: [],
    forbidden_spenders: [],
  },
};

const output = path.join(__dirname, "contract", "init-args.generated.json");
fs.writeFileSync(output, JSON.stringify(args, null, 2) + "\n", { mode: 0o600 });

console.log(`Wrote initialization arguments to ${output}`);
console.log(`Target account: ${contractId}`);
console.log("NEXT: inspect the JSON, deploy the WASM, and initialize this account exactly once.");
console.log("Do not run initialization against an account that is already initialized.");
console.log("Never put SENTRY_PRIVATE_KEY or any secret key in this generated file.");
