# evilcrypt

EvilCrypt is a collection of symmetric encryption algorithms that extend AES. Each algorithm version offers different parameters, such as key length, checksum length, or encryption speed, to suit various use cases.

## Getting started

You can install the package using your preferred package manager:

```bash
bun install evilcrypt
# or
pnpm install evilcrypt
# or
npm install evilcrypt
```

To encrypt and decrypt a string, follow this example:

```javascript
import { randomBytes } from 'node:crypto';
import {
    encrypt,
    decrypt,
} from 'evilcrypt';

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

By default, the `encrypt` method uses algorithm `v1`. If you want to use a different algorithm, call the encrypt method of that specific version:

```javascript
import { v2 as evilcrypt_v2 } from 'evilcrypt';

const message_encrypted = await evilcrypt_v2.encrypt(message_buffer, key);
```

For decryption, use the `decrypt` method from the core module. It automatically detects the algorithm used to encrypt the message.

```javascript
import { decrypt } from 'evilcrypt';

const message = await decrypt(message_encrypted, key);
```

## Algorithms

### v1

| Parameter              | Value         |
| ------------------     | ------------- |
| AES algorithm          | AES-256-CBC   |
| PBKDF2 algorithm       | PBKDF2-SHA256 |
| PBKDF2 iterations      | 100 000       |
| Message padding length | 8...255 bytes |
| Checksum algorithm     | SHA256        |
| Checksum length        | 32 bytes      |
| Key length             | 64 bytes      |

`v1` is inspired by [Telegram’s MTProto encryption](https://core.telegram.org/techfaq#q-how-does-server-client-encryption-work-in-mtproto). Its output is relatively long because it includes a 32-byte checksum and extensive padding. This makes it less suitable for encrypting short messages.

### v2

| Parameter                  | Value                |
| -------------------------- | -------------------- |
| AES algorithm              | AES-256-CBC          |
| PBKDF2 algorithm           | PBKDF2-SHA256        |
| PBKDF2 iterations          | 100 000              |
| Message padding length     | 6 bits + 4...7 bytes |
| Checksum algorithm         | PBKDF2-SHA256        |
| Checksum PBKDF2 iterations | 100 000              |
| Checksum length            | 12 bytes             |
| Key length                 | 64 bytes             |

`v2` is optimized for encrypting short messages, such as tokens. It produces shorter outputs compared to `v1` due to its reduced checksum length. However, the checksum is computed using PBKDF2 with 100 000 iterations, making brute-force attempts more difficult. The padding length is also minimized, with a maximum length of 62 bits.
