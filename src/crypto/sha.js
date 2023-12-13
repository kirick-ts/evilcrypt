
import * as crypto from 'node:crypto';

/**
 * Creates SHA256 hash.
 * @param {Buffer} buffer The buffer to hash.
 * @returns {Buffer} The SHA256 hash.
 */
export function sha256(buffer) {
	return crypto.createHash('sha256').update(buffer).digest();
}
