
import * as v1 from './versions/v1.js';

const VERSIONS = {
	1: v1,
};

/**
 * Encrypts a message with a key using default algorithm.
 * @async
 * @param {Buffer} message The message to encrypt.
 * @param {Buffer} key The key to encrypt with.
 * @returns {Buffer} The encrypted message.
 */
export async function encrypt(message, key) {
	return v1.encrypt(message, key);
}

/**
 * Decrypts a message with a key using algorithm specified in message.
 * @async
 * @param {*} message_encrypted The encrypted message to decrypt.
 * @param {*} key The key to decrypt with.
 * @returns {Buffer} The decrypted message.
 */
export async function decrypt(message_encrypted, key) {
	const evilcrypt_version_id = message_encrypted[0];
	const version = VERSIONS[evilcrypt_version_id];

	if (!version) {
		throw new Error(`Unknown evilcrypt version: ${evilcrypt_version_id}.`);
	}

	return version.decrypt(
		message_encrypted,
		key,
	);
}

export * as v1 from './versions/v1.js';
