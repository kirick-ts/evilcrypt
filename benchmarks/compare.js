
import { randomBytes }          from 'node:crypto';
import { encrypt as encryptV1 } from '../src/versions/v1.js';
import { encrypt as encryptV2 } from '../src/versions/v2.js';

const METHODS = {
	v1: encryptV1,
	v2: encryptV2,
};

const MESSAGE = randomBytes(
	16, // randomInt(16, 256),
);
const KEY = randomBytes(64);
const RUN_COUNT = 250;

for (const [ name, encrypt ] of Object.entries(METHODS)) {
	let length_total = 0;
	for (let run_id = 0; run_id < RUN_COUNT; run_id++) {
		// if (run_id % 10 === 0) {
		// 	console.log(`${name}: ${run_id}/${RUN_COUNT}`);
		// }

		// eslint-disable-next-line no-await-in-loop
		const result = await encrypt(MESSAGE, KEY);

		length_total += result.byteLength;
	}

	const length_average = length_total / RUN_COUNT;
	console.log(`${name}: average size is ${length_average} bytes`);
	console.log(`${name}: (${length_average / MESSAGE.byteLength}x overhead on plain message)`);
}
