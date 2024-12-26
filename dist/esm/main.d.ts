/**
 * Encrypts a message with a key using default algorithm.
 * @async
 * @param message - The message to encrypt.
 * @param key - The key to encrypt with.
 * @returns The encrypted message.
 */
export declare function encrypt(message: Buffer, key: Buffer): Promise<Buffer>;
/**
 * Decrypts a message with a key using algorithm specified in message.
 * @async
 * @param message_encrypted - The encrypted message to decrypt.
 * @param key - The key to decrypt with.
 * @returns The decrypted message.
 */
export declare function decrypt(message_encrypted: Buffer, key: Buffer): Promise<Buffer>;
export * as v1 from './versions/v1.js';
export * as v2 from './versions/v2.js';
