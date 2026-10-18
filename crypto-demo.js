const crypto = require('crypto');

// 1. Generate a fresh 256-bit AES key and a 12-byte nonce
const key = crypto.randomBytes(32);
const nonce = crypto.randomBytes(12);

// 2. Define the sample academic note
const plaintext =
    "Student consultation note – demonstration data only";

console.log("Original Plaintext:", plaintext);

// 3. Encrypt the note using AES-256-GCM
const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    nonce
);

let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
ciphertext += cipher.final('hex');

const authTag = cipher.getAuthTag();

console.log("\nEncrypted Ciphertext:", ciphertext);
console.log("Authentication Tag:", authTag.toString('hex'));

// 4. Decrypt the original ciphertext
try {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        nonce
    );

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    console.log("\nOriginal decryption successful:", decrypted);
} catch (error) {
    console.log("Original decryption failed.");
}

// 5. Modify one byte of the ciphertext
const tamperedBuffer = Buffer.from(ciphertext, 'hex');
tamperedBuffer[0] ^= 1;

const tamperedCiphertext = tamperedBuffer.toString('hex');

console.log("\nTampered Ciphertext:", tamperedCiphertext);

// 6. Attempt to decrypt the modified ciphertext
try {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        nonce
    );

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(
        tamperedCiphertext,
        'hex',
        'utf8'
    );

    decrypted += decipher.final('utf8');

    console.log("WARNING: Tampered ciphertext was accepted:", decrypted);
} catch (error) {
    console.log(
        "Tampering detected: decryption rejected because authentication failed."
    );
}
