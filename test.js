
const crypto = require('crypto');
const { evilcrypt } = require('./main.js');

(async () => {
	let iterations_count = 0;
	let time_encrypt = 0;
	let time_decrypt = 0;

	const hrtime = process.hrtime();
	while (true) { // eslint-disable-line no-constant-condition
		const message = crypto.randomBytes(
			// Math.trunc(Math.random() * 1000) + 24,
			25,
		);
		const key = crypto.randomBytes(64);

		const hrtime_encrypt = process.hrtime();
		const message_encrypted = await evilcrypt.encrypt(message, key); // eslint-disable-line no-await-in-loop
		{
			const [ seconds, nanoseconds ] = process.hrtime(hrtime_encrypt);
			time_encrypt += (seconds * 1e3) + (nanoseconds / 1e6);
		}

		const hrtime_decrypt = process.hrtime();
		const message_decrypted = await evilcrypt.decrypt(message_encrypted, key); // eslint-disable-line no-await-in-loop
		{
			const [ seconds, nanoseconds ] = process.hrtime(hrtime_decrypt);
			time_decrypt += (seconds * 1e3) + (nanoseconds / 1e6);
		}

		iterations_count++;

		if (message_decrypted.equals(message) !== true) {
			throw new Error('Invalid decryption.');
		}

		if (process.hrtime(hrtime)[0] >= 10) {
			break;
		}
	}

	console.log('iterations:', iterations_count);
	console.log('time per encrypt:', (time_encrypt / iterations_count).toFixed(2) + 'ms');
	console.log('time per decrypt:', (time_decrypt / iterations_count).toFixed(2) + 'ms');
})()
.catch(console.error);
