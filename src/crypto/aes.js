
import * as crypto from 'node:crypto';

/**
 * Encrypts data using AES.
 * @param {string} algorithm The algorithm to use.
 * @param {Buffer} iv The IV to use.
 * @param {Buffer} key The key to use.
 * @param {Buffer} data The data to encrypt.
 * @returns {Buffer} The encrypted data.
 */
export function encrypt(
	algorithm,
	iv,
	key,
	data,
) {
	const cipher = crypto.createCipheriv(
		algorithm,
		key,
		iv,
	);

	cipher.setAutoPadding(true);

	return Buffer.concat([
		cipher.update(data),
		cipher.final(),
	]);
}

/**
 * Decrypts data using AES.
 * @param {string} algorithm The algorithm to use.
 * @param {Buffer} iv The IV to use.
 * @param {Buffer} key The key to use.
 * @param {Buffer} data The data to decrypt.
 * @returns {Buffer} The decrypted data.
 */
export function decrypt(
	algorithm,
	iv,
	key,
	data,
) {
	const decipher = crypto.createDecipheriv(
		algorithm,
		key,
		iv,
	);

	decipher.setAutoPadding(true);

	return Buffer.concat([
		decipher.update(data),
		decipher.final(),
	]);
}

