/**
 * Encrypts a message using EvilCrypt algorithm #2.
 * @param message - The message to encrypt.
 * @param key - The 64 byte key to encrypt with.
 * @returns The encrypted message.
 */
export declare function encrypt(message: Buffer, key: Buffer): Promise<Buffer>;
/**
 * Decrypts a message using EvilCrypt algorithm #2.
 * @param message_encrypted - The encrypted message to decrypt.
 * @param key - The 64 byte key to decrypt with.
 * @returns The decrypted message.
 */
export declare function decrypt(message_encrypted: Buffer, key: Buffer): Promise<Buffer>;
