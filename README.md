
# evilcrypt

EvilCrypt is a collection of symmetric encryption algorithms that extends AES. Different versions of algorithms have different parameters such as key length, checksum length or speed.

## Getting started

First, install the package:

```bash
npm install evilcrypt
```

Then, use it. For example, to encrypt a string:

```javascript
import { randomBytes } from 'node:crypto';
import {
    encrypt,
    decrypt }          from 'evilcrypt';

const message = 'Hello world!';
const message_buffer = Buffer.from(message, 'utf8');

const key = randomBytes(64);

const message_encrypted = await encrypt(message_buffer, key);
console.log(message_encrypted);
// Buffer(65) [Uint8Array] [
//     1, 234, 250,  99, 214,  36, 216,  43,  65,  68,  85,
//    20,   8,   3, 152, 234, 206, 228,  14, 184, 101,  62,
//   132, 217,  56, 131, 167,  87, 112, 128,  87, 242,  39,
//   249,  12, 190, 100,  87,  91, 145,  49, 112,  51,  96,
//     7,  23, 181, 182, 210, 171, 244, 220,  98, 163, 207,
//    86,  78, 139,  26, 176, 238,  48,  44,  77,  20
// ]

const message_decrypted = await decrypt(message_encrypted, key);
console.log(message_decrypted.toString('utf8'));
// 'Hello world!'
```

By using `encrypt` method, you will encrypt a message using algorithm `#1`. To use other algorithms, use `encrypt` methods of the corresponding algorithm:

```javascript
import { v1 as evilcrypt_v1 } from 'evilcrypt';

const message_encrypted = await evilcrypt_v1.encrypt(message_buffer, key);
```

When decrypting, you can use `decrypt` directly from core module. It will automatically detect the algorithm used to encrypt the message.

## Algorithms

### #1

| Parameter          | Value         |
| ------------------ | ------------- |
| AES algorithm      | AES-256-CBC   |
| PBKDF2 algorithm   | PBKDF2-SHA256 |
| PBKDF2 iterations  | 100 000       |
| Checksum algorithm | SHA-256       |
| Checksum length    | 32 bytes      |
| Key length         | 64 bytes      |

The first and only algorithm for now inspired by [Telegram](https://core.telegram.org/techfaq#q-how-does-server-client-encryption-work-in-mtproto). Its output are pretty long because it contains 32-byte checksum, so it may be not suitable for short messages.
