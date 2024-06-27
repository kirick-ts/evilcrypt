/**
 * Encrypts a message with a key using default algorithm.
 * @async
 * @param {Buffer} message The message to encrypt.
 * @param {Buffer} key The key to encrypt with.
 * @returns {Promise<Buffer>} The encrypted message.
 */
export function encrypt(message: Buffer, key: Buffer): Promise<Buffer>;
/**
 * Decrypts a message with a key using algorithm specified in message.
 * @async
 * @param {any} message_encrypted The encrypted message to decrypt.
 * @param {any} key The key to decrypt with.
 * @returns {Promise<Buffer>} The decrypted message.
 */
export function decrypt(message_encrypted: any, key: any): Promise<Buffer>;
export * as v1 from "./versions/v1.js";
export * as v2 from "./versions/v2.js";
export type EvilcryptVersion = {
    /**
     * -
     */
    encrypt: (message: Buffer, key: Buffer) => Buffer | Promise<Buffer>;
    /**
     * -
     */
    decrypt: (message_encrypted: Buffer, key: Buffer) => Buffer | Promise<Buffer>;
};
