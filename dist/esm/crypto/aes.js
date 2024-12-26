import { createCipheriv, createDecipheriv, } from 'node:crypto';
/**
 * Encrypts data using AES.
 * @param algorithm - The algorithm to use.
 * @param iv - The IV to use.
 * @param key - The key to use.
 * @param data - The data to encrypt.
 * @returns The encrypted data.
 */
export function encrypt(algorithm, iv, key, data) {
    const cipher = createCipheriv(algorithm, key, iv);
    cipher.setAutoPadding(true);
    return Buffer.concat([
        cipher.update(data),
        cipher.final(),
    ]);
}
/**
 * Decrypts data using AES.
 * @param algorithm - The algorithm to use.
 * @param iv - The IV to use.
 * @param key - The key to use.
 * @param data - The data to decrypt.
 * @returns The decrypted data.
 */
export function decrypt(algorithm, iv, key, data) {
    const decipher = createDecipheriv(algorithm, key, iv);
    decipher.setAutoPadding(true);
    return Buffer.concat([
        decipher.update(data),
        decipher.final(),
    ]);
}
