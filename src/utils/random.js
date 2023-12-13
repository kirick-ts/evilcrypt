
import { randomBytes } from 'node:crypto';

const RANDOM_NUMBER_LIMIT = 4294967296; // 2^32, 4 bytes
export function randomInt(min_incl, max_not_incl) {
	const buffer = randomBytes(4);

	const max_from_zero = max_not_incl - min_incl;

	// eslint-disable-next-line no-bitwise
	const number = ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]) >>> 0;
	const number_max = RANDOM_NUMBER_LIMIT - (RANDOM_NUMBER_LIMIT % max_from_zero) - 1;

	if (number > number_max) {
		return randomInt(min_incl, max_not_incl);
	}

	return min_incl + (number % max_from_zero);
}
