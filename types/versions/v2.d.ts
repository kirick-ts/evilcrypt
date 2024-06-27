/**
 * Encrypts a message using EvilCrypt algorithm #2.
 * @param {Buffer} message The message to encrypt.
 * @param {Buffer} key The 64 byte key to encrypt with.
 * @returns {Promise<Buffer>} The encrypted message.
 */
export function encrypt(message: Buffer, key: Buffer): Promise<Buffer>;
/**
 * Decrypts a message using EvilCrypt algorithm #2.
 * @param {Buffer} message_encrypted The encrypted message to decrypt.
 * @param {Buffer} key The 64 byte key to decrypt with.
 * @returns {Promise<Buffer>} The decrypted message.
 */
export function decrypt(message_encrypted: Buffer, key: Buffer): Promise<Buffer>;
