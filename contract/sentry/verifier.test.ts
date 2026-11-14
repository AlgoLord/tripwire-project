import { TripwireVerifier } from "./verifier";
import { KeyPair } from "@near-js/crypto";
import * as assert from "assert";

console.log("Running TripwireVerifier unit tests...");

// Test 1: Successful signing with canonical binary format
const keyPair = KeyPair.fromRandom("ed25519");
const verifier = new TripwireVerifier(keyPair, keyPair.getPublicKey().toString());

const proposal = {
    nonce: 1n,
    payloadHashHex: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    derivationPath: "near,v3.tripwire-admin.testnet",
    transaction: { receiverId: "test.near", actions: [] }
};

const policy = { allowed_delegates: ["v3.tripwire-admin.testnet"], forbidden_spenders: [], max_eth_transfer: "1" };

const verdict = verifier.signProposal(proposal, policy);
assert.ok(verdict.signatureHex, "Signature hex should be present");
assert.ok(verdict.messageHex, "Message hex should be present");
assert.strictEqual(verdict.payloadHashHex, proposal.payloadHashHex, "Payload hash should match");
console.log("✓ Canonical binary signing test passed!");

// Test 2: Mismatched public key rejection
const wrongKeyPair = KeyPair.fromRandom("ed25519");
let threwError = false;
try {
    new TripwireVerifier(wrongKeyPair, "ed25519:wrong-public-key");
} catch (e: any) {
    if (e.message.includes("Verifier public key mismatch")) {
        threwError = true;
    }
}
assert.ok(threwError, "Should throw on public key mismatch");
console.log("✓ Public key mismatch rejection test passed!");

console.log("Tripwire verifier unit tests passed.");