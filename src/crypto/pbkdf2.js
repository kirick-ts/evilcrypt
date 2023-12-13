
import * as crypto from 'node:crypto';

/**
 * Creates a async wrapper around the pbkdf2 function.
 * @async
 * @param {Buffer} secret The secret to use.
 * @param {Buffer} salt The salt to use.
 * @param {number} iterations The number of iterations to use.
 * @param {number} key_length The length of the key to use.
 * @param {string?} [digest = 'sha256'] The digest to use. Defaults to 'sha256'.
 * @returns {Buffer} The derived key.
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
		crypto.pbkdf2(
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
