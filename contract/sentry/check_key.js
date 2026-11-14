const nacl = require('tweetnacl');
const { Buffer } = require('buffer');

// Function to test a candidate private key string (e.g., "ed25519:...")
function verifyCandidateKey(privateKeyStr, targetPublicKey) {
    try {
        // Strip the "ed25519:" prefix if present
        const cleanKey = privateKeyStr.replace('ed25519:', '');
        
        // Decode base64 private key
        const secretKeyBytes = Buffer.from(cleanKey, 'base64');
        
        // Extract 32-byte seed (first 32 bytes of the 64-byte Ed25519 secret key)
        const seed = secretKeyBytes.slice(0, 32);
        
        // Derive the keypair using tweetnacl
        const keyPair = nacl.sign.keyPair.fromSeed(seed);
        
        // Encode derived public key to base64 to match NEAR format
        const derivedPubKeyBase64 = Buffer.from(keyPair.publicKey).toString('base64');
        const formattedPubKey = `ed25519:${derivedPubKeyBase64}`;
        
        console.log(`Derived Public Key: ${formattedPubKey}`);
        console.log(`Target Public Key:  ${targetPublicKey}`);
        
        if (formattedPubKey === targetPublicKey) {
            console.log('\nSUCCESS: This private key EXACTLY matches your target public key!');
        } else {
            console.log('\nMISMATCH: This private key does not match the target public key.');
        }
    } catch (err) {
        console.error('Error parsing key:', err.message);
    }
}

// Test your candidate private key string here:
const candidate = process.env.TEST_KEY || "ed25519:REPLACE_WITH_YOUR_CANDIDATE_KEY";
verifyCandidateKey(candidate, "ed25519:Hub3G9ceAxYJFZwZ1RoSagtQNTNi8UBDWrDsR9J6GG3D");