
import {
	describe,
	test,
	expect }         from 'vitest';
import { randomInt } from './random.js';

describe('randomInt', () => {
	test('(0, 1)', () => {
		for (let run = 0; run < 10_000; run++) {
			expect(
				randomInt(0, 1),
			).toEqual(0);
		}
	});
	test('(0, 65536)', () => {
		for (let run = 0; run < 10_000; run++) {
			const result = randomInt(0, 65536);

			expect(result).toBeGreaterThanOrEqual(0);
			expect(result).toBeLessThan(65536);
		}
	});
});
