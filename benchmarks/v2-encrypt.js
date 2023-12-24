
import { encrypt } from '../src/versions/v2.js';

const message = Buffer.from('Hello, World!');
const key = Buffer.alloc(64, 0);

await encrypt(message, key);
