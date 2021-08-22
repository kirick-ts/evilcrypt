
const crypto = require('crypto');

const sha256 = exports.sha256 = async (buffer) => crypto.createHash('sha256').update(buffer).digest();

const pbkdf2 = exports.pbkdf2 = async (secret, salt, iterations, key_length, digest) => new Promise((resolve, reject) => {
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

const aes = exports.aes = {
	async encrypt (algorithm, iv, data, key) {
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
	},
	async decrypt (algorithm, iv, data, key) {
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
	},
};

const RANDOM_NUMBER_LIMIT = 4294967296;
const randomInt = exports.randomInt = (min_incl, max_not_incl) => {
	const buffer = crypto.randomBytes(4);

	const max_from_zero = max_not_incl - min_incl;

	const number = ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) >>> 0;
	const number_max = RANDOM_NUMBER_LIMIT - (RANDOM_NUMBER_LIMIT % max_from_zero) - 1;

	if (number > number_max) {
		return randomInt(min_incl, max_not_incl);
	}

	return min_incl + (number % max_from_zero);
};

exports.evilcrypt = {
	async encrypt (message, key) {
		return this.variants[1].encrypt(message, key);
	},
	async decrypt (payload_encrypted, key) {
		return this.variants[payload_encrypted[0]].decrypt(payload_encrypted, key);
	},
	variants: {
		1: {
			_aes_algorithm: 'aes-256-cbc',
			_version_id_buffer: Buffer.from([ 1 ]),

			async _getAESArgs (key_left, message_key) {
				const derived = await pbkdf2(
					key_left,
					message_key,
					100_000,
					64,
					'sha256',
				);

				return {
					aes_iv: derived.slice(0, 16),
					aes_key: derived.slice(32),
				};
			},

			async encrypt (message, key) {
				const message_length = message.byteLength;

				// 8-255 bytes
				const padding_length = randomInt(
					8,
					Math.min(
						Math.round(message_length * 0.4) + 12,
						256,
					),
				);
				const padding = crypto.randomBytes(padding_length);

				const payload = Buffer.concat([
					Buffer.from([
						padding_length,
					]),
					padding,
					message,
				]);

				const key_left = key.slice(0, 32);
				const key_right = key.slice(32);

				const message_key = await sha256(
					Buffer.concat([
						payload,
						key_right,
					]),
				);

				const { aes_iv, aes_key } = await this._getAESArgs(key_left, message_key);

				const payload_encrypted = await aes.encrypt(
					this._aes_algorithm,
					aes_iv,
					payload,
					aes_key,
				);

				return Buffer.concat([
					this._version_id_buffer,
					message_key,
					payload_encrypted,
				]);
			},
			async decrypt (message_encrypted, key) {
				const message_key = message_encrypted.slice(1, 33);
				const payload_encrypted = message_encrypted.slice(33);

				const key_left = key.slice(0, 32);
				const key_right = key.slice(32);

				const { aes_iv, aes_key } = await this._getAESArgs(key_left, message_key);

				const payload = await aes.decrypt(
					this._aes_algorithm,
					aes_iv,
					payload_encrypted,
					aes_key,
				);

				const message_key_check = await sha256(
					Buffer.concat([
						payload,
						key_right,
					]),
				);

				if (message_key_check.equals(message_key) !== true) {
					throw new Error('Decrypt error.');
				}

				return payload.slice(
					payload[0] + 1,
				);
			},
		},
	},
};
