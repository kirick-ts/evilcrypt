/**
 * Encrypts data using AES.
 * @param algorithm - The algorithm to use.
 * @param iv - The IV to use.
 * @param key - The key to use.
 * @param data - The data to encrypt.
 * @returns The encrypted data.
 */
export declare function encrypt(algorithm: string, iv: Buffer, key: Buffer, data: Buffer): Buffer;
/**
 * Decrypts data using AES.
 * @param algorithm - The algorithm to use.
 * @param iv - The IV to use.
 * @param key - The key to use.
 * @param data - The data to decrypt.
 * @returns The decrypted data.
 */
export declare function decrypt(algorithm: string, iv: Buffer, key: Buffer, data: Buffer): Buffer;
