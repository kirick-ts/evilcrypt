/**
 * Async version of the "crypto.pbkdf2" function.
 * @async
 * @param secret - The secret to use.
 * @param salt - The salt to use.
 * @param iterations - The number of iterations to use.
 * @param key_length - The length of the key to use.
 * @param digest - The digest to use. Default: `sha256`.
 * @returns The derived key.
 */
export declare function pbkdf2(secret: Buffer, salt: Buffer, iterations: number, key_length: number, digest?: string): Promise<Buffer>;
