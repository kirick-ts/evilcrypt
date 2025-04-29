import type { EvilcryptVersion } from './types.js';
import * as v1 from './versions/v1.js';
import * as v2 from './versions/v2.js';

const VERSIONS: Record<number, EvilcryptVersion | undefined> = {
	1: v1,
	2: v2,
};

/**
 * Encrypts a message with a key using default algorithm.
 * @async
 * @param message - The message to encrypt.
 * @param key - The key to encrypt with.
 * @returns The encrypted message.
 */
export function encrypt(
	message: Buffer,
	key: Buffer,
): Promise<Buffer> {
	return v1.encrypt(message, key);
}

/**
 * Decrypts a message with a key using algorithm specified in message.
 * @async
 * @param message_encrypted - The encrypted message to decrypt.
 * @param key - The key to decrypt with.
 * @returns The decrypted message.
 */
export function decrypt(
	message_encrypted: Buffer,
	key: Buffer,
): Promise<Buffer> {
	const evilcrypt_version_id = message_encrypted[0];
	const version = VERSIONS[evilcrypt_version_id];
	if (!version) {
		return Promise.reject(
			new Error(`Unknown evilcrypt version: ${evilcrypt_version_id}.`),
		);
	}

	return version.decrypt(
		message_encrypted,
		key,
	);
}

export * as v1 from './versions/v1.js';
export * as v2 from './versions/v2.js';
