import { createHash } from 'node:crypto';
/**
 * Creates SHA256 hash.
 * @param buffer - The buffer to hash.
 * @returns The SHA256 hash.
 */
export function sha256(buffer) {
    return createHash('sha256')
        .update(buffer)
        .digest();
}
