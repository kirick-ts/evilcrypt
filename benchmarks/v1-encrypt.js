
import { encrypt } from '../src/versions/v1.js';

const message = Buffer.from('Hello, World!');
const key = Buffer.alloc(64, 0);

await encrypt(message, key);
