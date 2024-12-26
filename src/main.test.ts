import { randomBytes } from 'node:crypto';
import {
	describe,
	test,
	expect,
} from 'vitest';
import {
	encrypt,
	decrypt,
	v1,
	v2,
} from './main.js';

const message = Buffer.from('Hello, world!');
const key = randomBytes(64);

const messages_encrypted = {
	default: null as Buffer | null,
	v1: null as Buffer | null,
	v2: null as Buffer | null,
};

describe('encrypt', () => {
	test('default algorithm (v1)', async () => {
		const message_encrypted = await encrypt(message, key);

		expect(message_encrypted[0]).toEqual(1);

		messages_encrypted.default = message_encrypted;
	});

	test('v1', async () => {
		const message_encrypted = await v1.encrypt(message, key);

		expect(message_encrypted[0]).toEqual(1);

		messages_encrypted.v1 = message_encrypted;
	});

	test('v2', async () => {
		const message_encrypted = await v2.encrypt(
			message,
			key,
		);

		expect(message_encrypted[0]).toEqual(2);

		messages_encrypted.v2 = message_encrypted;
	});
});

describe('decrypt', () => {
	for (const version of Object.keys(messages_encrypted)) {
		test(version, async () => {
			const message_decrypted = await decrypt(
				messages_encrypted[version],
				key,
			);

			expect(message_decrypted).toEqual(message);
		});
	}

	test('unknown version', async () => {
		const message_encrypted_copy = Buffer.from(
			messages_encrypted.default!,
		);
		message_encrypted_copy[0] = 255;

		const decrypt_promise = decrypt(
			message_encrypted_copy,
			key,
		);

		await expect(decrypt_promise).rejects.toThrow('Unknown evilcrypt version: 255.');
	});

	test('encrypted message from evilcrypt@0.1.0', async () => {
		const message_encrypted = Buffer.from(
			'AbzJIEowQknTzBzVyQ46NTF0z9M8a0+koddYU/jnbh+AaLKkjXHBzc0tRhnCrSsIiJif+bQ3P5avvFq8+SsZZrY=',
			'base64',
		);
		const key_local = Buffer.from(
			'cHYKhQ0Y4CKtheAarfMWD2JiGimR6xGJSEG23SKCjxhE3+XdyyRjPwF3QFz+KuQW+com20f2w/fKSSg7l0bddg==',
			'base64',
		);

		const message_decrypted = await decrypt(
			message_encrypted,
			key_local,
		);

		expect(message_decrypted).toEqual(message);
	});
});
