import { KeyPair } from "@near-js/crypto";
import * as dotenv from "dotenv";
import * as crypto from "crypto";

dotenv.config();

export type PolicyConfig = {
    [key: string]: any;
};

export type ProposalInput = {
    nonce: number | bigint;
    payloadHashHex?: string;
    payload?: string;
    derivationPath?: string;
    transaction?: any;
};

export class TripwireVerifier {
    private keyPair: KeyPair;
    private expectedPublicKey?: string;

    constructor(keyPair?: KeyPair | string, expectedPublicKey?: string) {
        if (typeof keyPair === "string") {
            this.keyPair = KeyPair.fromString(keyPair as any);
            this.expectedPublicKey = expectedPublicKey;
        } else if (keyPair) {
            this.keyPair = keyPair;
            this.expectedPublicKey = expectedPublicKey;
        } else {
            const privateKey = process.env.SENTRY_PRIVATE_KEY || process.env.ADMIN_PRIVATE_KEY || process.env.PRIVATE_KEY;
            if (!privateKey) {
                throw new Error("SENTRY_PRIVATE_KEY is not defined in environment variables.");
            }
            this.keyPair = KeyPair.fromString(privateKey as any);
        }

        if (this.expectedPublicKey && this.keyPair.getPublicKey().toString() !== this.expectedPublicKey) {
            throw new Error("Verifier public key mismatch");
        }
    }

    public signProposal(proposal: ProposalInput, policy: PolicyConfig): { signatureHex: string; messageHex: string; payloadHashHex: string } {
        const nonceNum = BigInt(proposal.nonce ?? 1);
        const nonceBuf = Buffer.alloc(8);
        nonceBuf.writeBigUInt64LE(nonceNum);

        const rawHash = proposal.payloadHashHex || proposal.payload || "0x0000000000000000000000000000000000000000000000000000000000000000";
        const cleanHash = rawHash.replace(/^0x/, "");
        const payloadHashBuf = Buffer.from(cleanHash, "hex");

        const derivationPath = proposal.derivationPath || "near,v3.tripwire-admin.testnet";
        const derivationPathBuf = Buffer.from(derivationPath, "utf8");
        
        const policyJson = JSON.stringify(policy);
        const policyHashBuf = crypto.createHash("sha256").update(policyJson).digest();

        const message = Buffer.concat([
            nonceBuf,
            payloadHashBuf,
            derivationPathBuf,
            policyHashBuf
        ]);

        const signature = this.keyPair.sign(message);

        return {
            signatureHex: Buffer.from(signature.signature).toString("hex"),
            messageHex: message.toString("hex"),
            payloadHashHex: rawHash,
        };
    }
}