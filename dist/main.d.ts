import { __export } from "./chunk-Cl8Af3a2.js";

//#region src/versions/v1.d.ts
declare namespace v1_d_exports {
  export { decrypt$2 as decrypt, encrypt$2 as encrypt };
}
/**
* Encrypts a message using EvilCrypt algorithm #1.
* @param message - The message to encrypt.
* @param key - The 64 byte key to encrypt with.
* @returns The encrypted message.
*/
declare function encrypt$2(message: Buffer, key: Buffer): Promise<Buffer>;

/**
* Decrypts a message using EvilCrypt algorithm #1.
* @param message_encrypted - The encrypted message to decrypt.
* @param key - The 64 byte key to decrypt with.
* @returns The decrypted message.
*/
declare function decrypt$2(message_encrypted: Buffer, key: Buffer): Promise<Buffer>;

//#endregion
//#region src/versions/v2.d.ts
declare namespace v2_d_exports {
  export { decrypt$1 as decrypt, encrypt$1 as encrypt };
}
/**
* Encrypts a message using EvilCrypt algorithm #2.
* @param message - The message to encrypt.
* @param key - The 64 byte key to encrypt with.
* @returns The encrypted message.
*/
declare function encrypt$1(message: Buffer, key: Buffer): Promise<Buffer>;

/**
* Decrypts a message using EvilCrypt algorithm #2.
* @param message_encrypted - The encrypted message to decrypt.
* @param key - The 64 byte key to decrypt with.
* @returns The decrypted message.
*/
declare function decrypt$1(message_encrypted: Buffer, key: Buffer): Promise<Buffer>;

//#endregion
//#region src/main.d.ts
/**
* Encrypts a message with a key using default algorithm.
* @async
* @param message - The message to encrypt.
* @param key - The key to encrypt with.
* @returns The encrypted message.
*/
declare function encrypt(message: Buffer, key: Buffer): Promise<Buffer>;

/**
* Decrypts a message with a key using algorithm specified in message.
* @async
* @param message_encrypted - The encrypted message to decrypt.
* @param key - The key to decrypt with.
* @returns The decrypted message.
*/
declare function decrypt(message_encrypted: Buffer, key: Buffer): Promise<Buffer>;

//#endregion
export { decrypt, encrypt, v1_d_exports as v1, v2_d_exports as v2 };