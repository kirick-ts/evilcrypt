import { pbkdf2 as nodePbkdf2 } from 'node:crypto';

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
// eslint-disable-next-line @typescript-eslint/max-params
export function pbkdf2(
	secret: Buffer,
	salt: Buffer,
	iterations: number,
	key_length: number,
	digest: string = 'sha256',
): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		nodePbkdf2(
			secret,
			salt,
			iterations,
			key_length,
			digest,
			(error, derived_key) => {
				if (error) {
					reject(error);
				}
				else {
					resolve(derived_key);
				}
			},
		);
	});
}
