/**
 * Encrypts data using AES.
 * @param {string} algorithm The algorithm to use.
 * @param {Buffer} iv The IV to use.
 * @param {Buffer} key The key to use.
 * @param {Buffer} data The data to encrypt.
 * @returns {Buffer} The encrypted data.
 */
export function encrypt(algorithm: string, iv: Buffer, key: Buffer, data: Buffer): Buffer;
/**
 * Decrypts data using AES.
 * @param {string} algorithm The algorithm to use.
 * @param {Buffer} iv The IV to use.
 * @param {Buffer} key The key to use.
 * @param {Buffer} data The data to decrypt.
 * @returns {Buffer} The decrypted data.
 */
export function decrypt(algorithm: string, iv: Buffer, key: Buffer, data: Buffer): Buffer;
