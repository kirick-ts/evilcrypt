
import { pbkdf2 as nodePbkdf2 } from 'node:crypto';

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
// eslint-disable-next-line max-params
export async function pbkdf2(
	secret,
	salt,
	iterations,
	key_length,
	digest = 'sha256',
) {
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
