
/* global describe, test, expect */

import { randomBytes } from 'node:crypto';
import {
	encrypt,
	decrypt }          from './v2.js';

const message = Buffer.from('Hello, World!');
const key = randomBytes(64);
let message_encrypted;

describe('encrypt', () => {
	test('default message', async () => {
		message_encrypted = await encrypt(message, key);
	});

	test('key of wrong length', async () => {
		const encrypt_promise = encrypt(
			randomBytes(64),
			randomBytes(32),
		);

		await expect(encrypt_promise).rejects.toThrow();
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

		await expect(decrypt_promise).rejects.toThrow();
	});
});
