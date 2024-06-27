/**
 * Creates a async wrapper around the pbkdf2 function.
 * @async
 * @param {Buffer} secret The secret to use.
 * @param {Buffer} salt The salt to use.
 * @param {number} iterations The number of iterations to use.
 * @param {number} key_length The length of the key to use.
 * @param {string?} [digest] The digest to use. Default: `sha256`.
 * @returns {Promise<Buffer>} The derived key.
 */
export function pbkdf2(secret: Buffer, salt: Buffer, iterations: number, key_length: number, digest?: string | null): Promise<Buffer>;
