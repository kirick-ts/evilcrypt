
/* global describe, test, expect */

import { randomBytes } from 'node:crypto';
import {
	encrypt,
	decrypt }          from './main.js';

const message = Buffer.from('Hello, world!');
const key = randomBytes(64);
let message_encrypted;

describe('encrypt', () => {
	test('default message', async () => {
		message_encrypted = await encrypt(message, key);
	});
});

describe('decrypt', () => {
	test('default message', async () => {
		const message_decrypted = await decrypt(message_encrypted, key);

		expect(message_decrypted).toEqual(message);
	});

	test('wrong version', async () => {
		const message_encrypted_copy = Buffer.from(message_encrypted);
		message_encrypted_copy[0] = 255;

		const decrypt_promise = decrypt(
			message_encrypted_copy,
			key,
		);

		await expect(decrypt_promise).rejects.toThrow();
	});

	test('encrypted message from evilcrypt@0.1.0', async () => {
		const message_encrypted = Buffer.from(
			'AbzJIEowQknTzBzVyQ46NTF0z9M8a0+koddYU/jnbh+AaLKkjXHBzc0tRhnCrSsIiJif+bQ3P5avvFq8+SsZZrY=',
			'base64',
		);
		const key = Buffer.from(
			'cHYKhQ0Y4CKtheAarfMWD2JiGimR6xGJSEG23SKCjxhE3+XdyyRjPwF3QFz+KuQW+com20f2w/fKSSg7l0bddg==',
			'base64',
		);

		const message_decrypted = await decrypt(
			message_encrypted,
			key,
		);

		expect(message_decrypted).toEqual(message);
	});
});
