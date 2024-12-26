import { randomBytes } from 'node:crypto';
import * as aes from '../crypto/aes.js';
import { pbkdf2 } from '../crypto/pbkdf2.js';
import { sha256 } from '../crypto/sha.js';
import { randomInt } from '../utils/random.js';
const VERSION_ID_BUFFER = Buffer.from([1]);
const AES_ALGORITHM = 'aes-256-cbc';
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_LENGTH = 64;
const PBKDF2_DIGEST = 'sha256';
/**
 * Derives AES initialization vector and key.
 * @param key_left - The left 32 bytes of the key.
 * @param message_key - The message key.
 * @returns The AES arguments.
 */
async function getAesArguments(key_left, message_key) {
    const derived = await pbkdf2(key_left, message_key, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH, PBKDF2_DIGEST);
    return {
        aes_iv: derived.subarray(0, 16),
        aes_key: derived.subarray(32),
    };
}
/**
 * Encrypts a message using EvilCrypt algorithm #1.
 * @param message - The message to encrypt.
 * @param key - The 64 byte key to encrypt with.
 * @returns The encrypted message.
 */
export async function encrypt(message, key) {
    if (key.byteLength !== 64) {
        throw new Error('Key must be 64 bytes.');
    }
    const message_length = message.byteLength;
    // 8-255 bytes
    const padding_length = randomInt(8, Math.min(Math.round(message_length * 0.4) + 12, 256));
    const padding = randomBytes(padding_length);
    const payload = Buffer.concat([
        Buffer.from([
            padding_length,
        ]),
        padding,
        message,
    ]);
    const key_left = key.subarray(0, 32);
    const key_right = key.subarray(32);
    const message_key = sha256(Buffer.concat([
        payload,
        key_right,
    ]));
    const { aes_iv, aes_key, } = await getAesArguments(key_left, message_key);
    let payload_encrypted;
    try {
        payload_encrypted = aes.encrypt(AES_ALGORITHM, aes_iv, aes_key, payload);
    }
    catch {
        throw new Error('Encrypt error.');
    }
    return Buffer.concat([
        VERSION_ID_BUFFER,
        message_key,
        payload_encrypted,
    ]);
}
/**
 * Decrypts a message using EvilCrypt algorithm #1.
 * @param message_encrypted - The encrypted message to decrypt.
 * @param key - The 64 byte key to decrypt with.
 * @returns The decrypted message.
 */
export async function decrypt(message_encrypted, key) {
    if (key.byteLength !== 64) {
        throw new Error('Key must be 64 bytes.');
    }
    const message_key = message_encrypted.subarray(1, 33);
    const payload_encrypted = message_encrypted.subarray(33);
    const key_left = key.subarray(0, 32);
    const key_right = key.subarray(32);
    const { aes_iv, aes_key, } = await getAesArguments(key_left, message_key);
    let payload;
    try {
        payload = aes.decrypt(AES_ALGORITHM, aes_iv, aes_key, payload_encrypted);
    }
    catch {
        throw new Error('Decrypt error.');
    }
    const message_key_check = sha256(Buffer.concat([
        payload,
        key_right,
    ]));
    if (message_key_check.equals(message_key) !== true) {
        throw new Error('Decrypt error.');
    }
    return payload.subarray(payload[0] + 1);
}
