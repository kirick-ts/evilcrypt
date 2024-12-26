import { randomBytes } from 'node:crypto';
import * as aes from '../crypto/aes.js';
import { pbkdf2 } from '../crypto/pbkdf2.js';
import type { AesArgs } from '../types.js';

const VERSION_ID_BUFFER = Buffer.from([ 2 ]);

const AES_ALGORITHM = 'aes-256-cbc';

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_MESSAGE_KEY_LENGTH = 12;
const PBKDF2_AES_KEY_LENGTH = 64;
const PBKDF2_DIGEST = 'sha256';

/**
 * Derives the message key.
 * @param payload - The payload to derive the message key from.
 * @param key_right - The right 32 bytes of the key.
 * @returns The message key.
 */
function getMessageKey(
	payload: Buffer,
	key_right: Buffer,
): Promise<Buffer> {
	return pbkdf2(
		payload,
		key_right,
		PBKDF2_ITERATIONS,
		PBKDF2_MESSAGE_KEY_LENGTH,
		PBKDF2_DIGEST,
	);
}

/**
 * Derives AES initialization vector and key.
 * @param key_left - The left 32 bytes of the key.
 * @param message_key - The message key.
 * @returns The AES arguments.
 */
async function getAesArguments(
	key_left: Buffer,
	message_key: Buffer,
): Promise<AesArgs> {
	const derived = await pbkdf2(
		key_left,
		message_key,
		PBKDF2_ITERATIONS,
		PBKDF2_AES_KEY_LENGTH,
		PBKDF2_DIGEST,
	);

	return {
		aes_iv: derived.subarray(0, 16),
		aes_key: derived.subarray(32),
	};
}

/**
 * Encrypts a message using EvilCrypt algorithm #2.
 * @param message - The message to encrypt.
 * @param key - The 64 byte key to encrypt with.
 * @returns The encrypted message.
 */
export async function encrypt(
	message: Buffer,
	key: Buffer,
): Promise<Buffer> {
	if (key.byteLength !== 64) {
		throw new Error('Key must be 64 bytes.');
	}

	// 4-7 bytes
	// first byte of padding contains
	// - 2 bits of additional padding length (values 0-3)
	// - 6 random bits
	const padding_bytes_meta = randomBytes(1);
	const padding_additional_bytes_count = padding_bytes_meta[0] >>> 6; // eslint-disable-line no-bitwise

	const payload = Buffer.concat([
		padding_bytes_meta,
		randomBytes(4 + padding_additional_bytes_count),
		message,
	]);

	const key_left = key.subarray(0, 32);
	const key_right = key.subarray(32);

	const message_key = await getMessageKey(payload, key_right);

	const {
		aes_iv,
		aes_key,
	} = await getAesArguments(key_left, message_key);

	let payload_encrypted: Buffer;
	try {
		payload_encrypted = aes.encrypt(
			AES_ALGORITHM,
			aes_iv,
			aes_key,
			payload,
		);
	}
	catch {
		throw new Error('Encrypt error.');
	}

	return Buffer.concat([
		VERSION_ID_BUFFER,
		message_key,
		payload_encrypted,
	]);
}

/**
 * Decrypts a message using EvilCrypt algorithm #2.
 * @param message_encrypted - The encrypted message to decrypt.
 * @param key - The 64 byte key to decrypt with.
 * @returns The decrypted message.
 */
export async function decrypt(
	message_encrypted: Buffer,
	key: Buffer,
): Promise<Buffer> {
	if (key.byteLength !== 64) {
		throw new Error('Key must be 64 bytes.');
	}

	const message_key = message_encrypted.subarray(
		1,
		PBKDF2_MESSAGE_KEY_LENGTH + 1,
	);
	const payload_encrypted = message_encrypted.subarray(PBKDF2_MESSAGE_KEY_LENGTH + 1);

	const key_left = key.subarray(0, 32);
	const key_right = key.subarray(32);

	const {
		aes_iv,
		aes_key,
	} = await getAesArguments(key_left, message_key);

	let payload: Buffer;
	try {
		payload = aes.decrypt(
			AES_ALGORITHM,
			aes_iv,
			aes_key,
			payload_encrypted,
		);
	}
	catch {
		throw new Error('Decrypt error.');
	}

	const message_key_check = await getMessageKey(payload, key_right);

	if (message_key_check.equals(message_key) !== true) {
		throw new Error('Decrypt error.');
	}

	return payload.subarray(
		4 + (payload[0] >>> 6) + 1, // eslint-disable-line no-bitwise
	);
}
