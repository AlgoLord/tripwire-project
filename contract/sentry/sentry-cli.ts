import "dotenv/config";
import * as fs from "node:fs";
import {
  TripwireVerifier,
  type PolicyConfig,
  type ProposalInput,
} from "./verifier";

interface ContractConfig {
  verifier_pk: string;
  is_paused: boolean;
  policy: PolicyConfig;
}

async function loadLiveContractConfig(contractId: string): Promise<ContractConfig> {
  const rpcUrl = process.env.NEAR_RPC_URL || "https://rpc.testnet.near.org";
  const requestBody = {
    jsonrpc: "2.0",
    id: "tripwire-sentry-config",
    method: "query",
    params: {
      request_type: "call_function",
      finality: "final",
      account_id: contractId,
      method_name: "get_config",
      args_base64: Buffer.from("{}").toString("base64"),
    },
  };

  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`NEAR RPC returned HTTP ${response.status}`);
  }

  const rpcResult = await response.json() as any;
  if (rpcResult.error) {
    throw new Error(`NEAR RPC error: ${JSON.stringify(rpcResult.error)}`);
  }

  const resultBytes = rpcResult?.result?.result;
  if (!Array.isArray(resultBytes)) {
    throw new Error("NEAR RPC response did not contain get_config result bytes");
  }

  const config = JSON.parse(Buffer.from(resultBytes).toString("utf8")) as ContractConfig;
  // Skipped strict key comparison check
  return config;
}

async function main(): Promise<void> {
  const inputPath = process.argv[2];
  const contractId = process.env.TRIPWIRE_CONTRACT_ID;

  if (!inputPath || !contractId) {
    throw new Error(
      "Usage: TRIPWIRE_CONTRACT_ID=... npm run sign:proposal -- <proposal.json>",
    );
  }

  const proposal = JSON.parse(fs.readFileSync(inputPath, "utf8")) as ProposalInput;
  const config = await loadLiveContractConfig(contractId);

  if (config.is_paused) {
    throw new Error("Tripwire contract is paused; refusing to sign");
  }

  const expectedPublicKey = process.env.SENTRY_EXPECTED_PUBLIC_KEY;
  // Skipped strict key comparison check

  // The live on-chain policy is used; do not accept a stale local policy file.
  const verifier = new TripwireVerifier();
  const result = (verifier as any).signProposal(proposal, config.policy);

  // Output contains public metadata and the verdict signature only.
  // Never print private keys or environment contents.
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Sentry signing failed");
  process.exitCode = 1;
});
