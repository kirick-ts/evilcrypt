export interface EvilcryptVersion {
    encrypt: (message: Buffer, key: Buffer) => Promise<Buffer>;
    decrypt: (message_encrypted: Buffer, key: Buffer) => Promise<Buffer>;
}
export interface AesArgs {
    aes_iv: Buffer;
    aes_key: Buffer;
}
