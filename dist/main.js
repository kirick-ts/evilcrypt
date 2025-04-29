import { __export } from "./chunk-Cl8Af3a2.js";
import { createCipheriv, createDecipheriv, createHash, pbkdf2, randomBytes } from "node:crypto";

//#region src/crypto/aes.ts
/**
* Encrypts data using AES.
* @param algorithm - The algorithm to use.
* @param iv - The IV to use.
* @param key - The key to use.
* @param data - The data to encrypt.
* @returns The encrypted data.
*/
function encrypt$3(algorithm, iv, key, data) {
	const cipher = createCipheriv(algorithm, key, iv);
	cipher.setAutoPadding(true);
	return Buffer.concat([cipher.update(data), cipher.final()]);
}
/**
* Decrypts data using AES.
* @param algorithm - The algorithm to use.
* @param iv - The IV to use.
* @param key - The key to use.
* @param data - The data to decrypt.
* @returns The decrypted data.
*/
function decrypt$3(algorithm, iv, key, data) {
	const decipher = createDecipheriv(algorithm, key, iv);
	decipher.setAutoPadding(true);
	return Buffer.concat([decipher.update(data), decipher.final()]);
}

//#endregion
//#region src/crypto/pbkdf2.ts
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
function pbkdf2$1(secret, salt, iterations, key_length, digest = "sha256") {
	return new Promise((resolve, reject) => {
		pbkdf2(secret, salt, iterations, key_length, digest, (error, derived_key) => {
			if (error) reject(error);
			else resolve(derived_key);
		});
	});
}

//#endregion
//#region src/crypto/sha.ts
/**
* Creates SHA256 hash.
* @param buffer - The buffer to hash.
* @returns The SHA256 hash.
*/
function sha256(buffer) {
	return createHash("sha256").update(buffer).digest();
}

//#endregion
//#region src/utils/random.ts
const RANDOM_NUMBER_LIMIT = 4294967296;
/**
* @param min_incl - Minimum value to return.
* @param max_not_incl - Maximum value to return (not inclusive).
* @returns -
*/
function randomInt(min_incl, max_not_incl) {
	const buffer = randomBytes(4);
	const max_from_zero = max_not_incl - min_incl;
	const number = (buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]) >>> 0;
	const number_max = RANDOM_NUMBER_LIMIT - RANDOM_NUMBER_LIMIT % max_from_zero - 1;
	if (number > number_max) return randomInt(min_incl, max_not_incl);
	return min_incl + number % max_from_zero;
}

//#endregion
//#region src/versions/v1.ts
var v1_exports = {};
__export(v1_exports, {
	decrypt: () => decrypt$2,
	encrypt: () => encrypt$2
});
const VERSION_ID_BUFFER$1 = Buffer.from([1]);
const AES_ALGORITHM$1 = "aes-256-cbc";
const PBKDF2_ITERATIONS$1 = 1e5;
const PBKDF2_KEY_LENGTH = 64;
const PBKDF2_DIGEST$1 = "sha256";
/**
* Derives AES initialization vector and key.
* @param key_left - The left 32 bytes of the key.
* @param message_key - The message key.
* @returns The AES arguments.
*/
async function getAesArguments$1(key_left, message_key) {
	const derived = await pbkdf2$1(key_left, message_key, PBKDF2_ITERATIONS$1, PBKDF2_KEY_LENGTH, PBKDF2_DIGEST$1);
	return {
		aes_iv: derived.subarray(0, 16),
		aes_key: derived.subarray(32)
	};
}
/**
* Encrypts a message using EvilCrypt algorithm #1.
* @param message - The message to encrypt.
* @param key - The 64 byte key to encrypt with.
* @returns The encrypted message.
*/
async function encrypt$2(message, key) {
	if (key.byteLength !== 64) throw new Error("Key must be 64 bytes.");
	const message_length = message.byteLength;
	const padding_length = randomInt(8, Math.min(Math.round(message_length * .4) + 12, 256));
	const padding = randomBytes(padding_length);
	const payload = Buffer.concat([
		Buffer.from([padding_length]),
		padding,
		message
	]);
	const key_left = key.subarray(0, 32);
	const key_right = key.subarray(32);
	const message_key = sha256(Buffer.concat([payload, key_right]));
	const { aes_iv, aes_key } = await getAesArguments$1(key_left, message_key);
	let payload_encrypted;
	try {
		payload_encrypted = encrypt$3(AES_ALGORITHM$1, aes_iv, aes_key, payload);
	} catch {
		throw new Error("Encrypt error.");
	}
	return Buffer.concat([
		VERSION_ID_BUFFER$1,
		message_key,
		payload_encrypted
	]);
}
/**
* Decrypts a message using EvilCrypt algorithm #1.
* @param message_encrypted - The encrypted message to decrypt.
* @param key - The 64 byte key to decrypt with.
* @returns The decrypted message.
*/
async function decrypt$2(message_encrypted, key) {
	if (key.byteLength !== 64) throw new Error("Key must be 64 bytes.");
	const message_key = message_encrypted.subarray(1, 33);
	const payload_encrypted = message_encrypted.subarray(33);
	const key_left = key.subarray(0, 32);
	const key_right = key.subarray(32);
	const { aes_iv, aes_key } = await getAesArguments$1(key_left, message_key);
	let payload;
	try {
		payload = decrypt$3(AES_ALGORITHM$1, aes_iv, aes_key, payload_encrypted);
	} catch {
		throw new Error("Decrypt error.");
	}
	const message_key_check = sha256(Buffer.concat([payload, key_right]));
	if (message_key_check.equals(message_key) !== true) throw new Error("Decrypt error.");
	return payload.subarray(payload[0] + 1);
}

//#endregion
//#region src/versions/v2.ts
var v2_exports = {};
__export(v2_exports, {
	decrypt: () => decrypt$1,
	encrypt: () => encrypt$1
});
const VERSION_ID_BUFFER = Buffer.from([2]);
const AES_ALGORITHM = "aes-256-cbc";
const PBKDF2_ITERATIONS = 1e5;
const PBKDF2_MESSAGE_KEY_LENGTH = 12;
const PBKDF2_AES_KEY_LENGTH = 64;
const PBKDF2_DIGEST = "sha256";
/**
* Derives the message key.
* @param payload - The payload to derive the message key from.
* @param key_right - The right 32 bytes of the key.
* @returns The message key.
*/
function getMessageKey(payload, key_right) {
	return pbkdf2$1(payload, key_right, PBKDF2_ITERATIONS, PBKDF2_MESSAGE_KEY_LENGTH, PBKDF2_DIGEST);
}
/**
* Derives AES initialization vector and key.
* @param key_left - The left 32 bytes of the key.
* @param message_key - The message key.
* @returns The AES arguments.
*/
async function getAesArguments(key_left, message_key) {
	const derived = await pbkdf2$1(key_left, message_key, PBKDF2_ITERATIONS, PBKDF2_AES_KEY_LENGTH, PBKDF2_DIGEST);
	return {
		aes_iv: derived.subarray(0, 16),
		aes_key: derived.subarray(32)
	};
}
/**
* Encrypts a message using EvilCrypt algorithm #2.
* @param message - The message to encrypt.
* @param key - The 64 byte key to encrypt with.
* @returns The encrypted message.
*/
async function encrypt$1(message, key) {
	if (key.byteLength !== 64) throw new Error("Key must be 64 bytes.");
	const padding_bytes_meta = randomBytes(1);
	const padding_additional_bytes_count = padding_bytes_meta[0] >>> 6;
	const payload = Buffer.concat([
		padding_bytes_meta,
		randomBytes(4 + padding_additional_bytes_count),
		message
	]);
	const key_left = key.subarray(0, 32);
	const key_right = key.subarray(32);
	const message_key = await getMessageKey(payload, key_right);
	const { aes_iv, aes_key } = await getAesArguments(key_left, message_key);
	let payload_encrypted;
	try {
		payload_encrypted = encrypt$3(AES_ALGORITHM, aes_iv, aes_key, payload);
	} catch {
		throw new Error("Encrypt error.");
	}
	return Buffer.concat([
		VERSION_ID_BUFFER,
		message_key,
		payload_encrypted
	]);
}
/**
* Decrypts a message using EvilCrypt algorithm #2.
* @param message_encrypted - The encrypted message to decrypt.
* @param key - The 64 byte key to decrypt with.
* @returns The decrypted message.
*/
async function decrypt$1(message_encrypted, key) {
	if (key.byteLength !== 64) throw new Error("Key must be 64 bytes.");
	const message_key = message_encrypted.subarray(1, PBKDF2_MESSAGE_KEY_LENGTH + 1);
	const payload_encrypted = message_encrypted.subarray(PBKDF2_MESSAGE_KEY_LENGTH + 1);
	const key_left = key.subarray(0, 32);
	const key_right = key.subarray(32);
	const { aes_iv, aes_key } = await getAesArguments(key_left, message_key);
	let payload;
	try {
		payload = decrypt$3(AES_ALGORITHM, aes_iv, aes_key, payload_encrypted);
	} catch {
		throw new Error("Decrypt error.");
	}
	const message_key_check = await getMessageKey(payload, key_right);
	if (message_key_check.equals(message_key) !== true) throw new Error("Decrypt error.");
	return payload.subarray(4 + (payload[0] >>> 6) + 1);
}

//#endregion
//#region src/main.ts
const VERSIONS = {
	1: v1_exports,
	2: v2_exports
};
/**
* Encrypts a message with a key using default algorithm.
* @async
* @param message - The message to encrypt.
* @param key - The key to encrypt with.
* @returns The encrypted message.
*/
function encrypt(message, key) {
	return encrypt$2(message, key);
}
/**
* Decrypts a message with a key using algorithm specified in message.
* @async
* @param message_encrypted - The encrypted message to decrypt.
* @param key - The key to decrypt with.
* @returns The decrypted message.
*/
function decrypt(message_encrypted, key) {
	const evilcrypt_version_id = message_encrypted[0];
	const version = VERSIONS[evilcrypt_version_id];
	if (!version) return Promise.reject(new Error(`Unknown evilcrypt version: ${evilcrypt_version_id}.`));
	return version.decrypt(message_encrypted, key);
}

//#endregion
export { decrypt, encrypt, v1_exports as v1, v2_exports as v2 };