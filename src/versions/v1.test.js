
/* global describe, test, expect */

import { randomBytes } from 'node:crypto';
import {
	encrypt,
	decrypt }          from './v1.js';

const message = Buffer.from('Hello, World!');
const key = randomBytes(64);
let message_encrypted;

async function expectPromiseReject(promise) {
	let error;
	try {
		await promise;
	}
	catch (error_) {
		error = error_;
	}

	expect(error).toBeInstanceOf(Error);
}

describe('encrypt', () => {
	test('default message', async () => {
		message_encrypted = await encrypt(message, key);
	});

	test('key of wrong length', async () => {
		const encrypt_promise = encrypt(
			randomBytes(64),
			randomBytes(32),
		);

		// FIXME: Bun throws with "Expected value must be a function" error.
		// await expect(encrypt_promise).rejects.toThrow();
		await expectPromiseReject(encrypt_promise);
	});
});

describe('decrypt', () => {
	test('default message', async () => {
		const message_decrypted = await decrypt(message_encrypted, key);

		expect(message_decrypted).toEqual(message);
	});

	test('wrong key', async () => {
		const decrypt_promise = decrypt(
			message_encrypted,
			randomBytes(64),
		);

		// FIXME: Bun throws with "Expected value must be a function" error.
		// await expect(decrypt_promise).rejects.toThrow();
		await expectPromiseReject(decrypt_promise);
	});
});
