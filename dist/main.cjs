var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __moduleCache = /* @__PURE__ */ new WeakMap;
var __toCommonJS = (from) => {
  var entry = __moduleCache.get(from), desc;
  if (entry)
    return entry;
  entry = __defProp({}, "__esModule", { value: true });
  if (from && typeof from === "object" || typeof from === "function")
    __getOwnPropNames(from).map((key) => !__hasOwnProp.call(entry, key) && __defProp(entry, key, {
      get: () => from[key],
      enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
    }));
  __moduleCache.set(from, entry);
  return entry;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: (newValue) => all[name] = () => newValue
    });
};

// dist/esm/main.js
var exports_main = {};
__export(exports_main, {
  v2: () => exports_v2,
  v1: () => exports_v1,
  encrypt: () => encrypt4,
  decrypt: () => decrypt4
});
module.exports = __toCommonJS(exports_main);

// dist/esm/versions/v1.js
var exports_v1 = {};
__export(exports_v1, {
  encrypt: () => encrypt2,
  decrypt: () => decrypt2
});
var import_node_crypto5 = require("node:crypto");

// dist/esm/crypto/aes.js
var import_node_crypto = require("node:crypto");
function encrypt(algorithm, iv, key, data) {
  const cipher = import_node_crypto.createCipheriv(algorithm, key, iv);
  cipher.setAutoPadding(true);
  return Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);
}
function decrypt(algorithm, iv, key, data) {
  const decipher = import_node_crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAutoPadding(true);
  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}

// dist/esm/crypto/pbkdf2.js
var import_node_crypto2 = require("node:crypto");
function pbkdf2(secret, salt, iterations, key_length, digest = "sha256") {
  return new Promise((resolve, reject) => {
    import_node_crypto2.pbkdf2(secret, salt, iterations, key_length, digest, (error, derived_key) => {
      if (error) {
        reject(error);
      } else {
        resolve(derived_key);
      }
    });
  });
}

// dist/esm/crypto/sha.js
var import_node_crypto3 = require("node:crypto");
function sha256(buffer) {
  return import_node_crypto3.createHash("sha256").update(buffer).digest();
}

// dist/esm/utils/random.js
var import_node_crypto4 = require("node:crypto");
var RANDOM_NUMBER_LIMIT = 4294967296;
function randomInt(min_incl, max_not_incl) {
  const buffer = import_node_crypto4.randomBytes(4);
  const max_from_zero = max_not_incl - min_incl;
  const number = (buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]) >>> 0;
  const number_max = RANDOM_NUMBER_LIMIT - RANDOM_NUMBER_LIMIT % max_from_zero - 1;
  if (number > number_max) {
    return randomInt(min_incl, max_not_incl);
  }
  return min_incl + number % max_from_zero;
}

// dist/esm/versions/v1.js
var VERSION_ID_BUFFER = Buffer.from([1]);
var AES_ALGORITHM = "aes-256-cbc";
var PBKDF2_ITERATIONS = 1e5;
var PBKDF2_KEY_LENGTH = 64;
var PBKDF2_DIGEST = "sha256";
async function getAesArguments(key_left, message_key) {
  const derived = await pbkdf2(key_left, message_key, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH, PBKDF2_DIGEST);
  return {
    aes_iv: derived.subarray(0, 16),
    aes_key: derived.subarray(32)
  };
}
async function encrypt2(message, key) {
  if (key.byteLength !== 64) {
    throw new Error("Key must be 64 bytes.");
  }
  const message_length = message.byteLength;
  const padding_length = randomInt(8, Math.min(Math.round(message_length * 0.4) + 12, 256));
  const padding = import_node_crypto5.randomBytes(padding_length);
  const payload = Buffer.concat([
    Buffer.from([
      padding_length
    ]),
    padding,
    message
  ]);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const message_key = sha256(Buffer.concat([
    payload,
    key_right
  ]));
  const { aes_iv, aes_key } = await getAesArguments(key_left, message_key);
  let payload_encrypted;
  try {
    payload_encrypted = encrypt(AES_ALGORITHM, aes_iv, aes_key, payload);
  } catch {
    throw new Error("Encrypt error.");
  }
  return Buffer.concat([
    VERSION_ID_BUFFER,
    message_key,
    payload_encrypted
  ]);
}
async function decrypt2(message_encrypted, key) {
  if (key.byteLength !== 64) {
    throw new Error("Key must be 64 bytes.");
  }
  const message_key = message_encrypted.subarray(1, 33);
  const payload_encrypted = message_encrypted.subarray(33);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const { aes_iv, aes_key } = await getAesArguments(key_left, message_key);
  let payload;
  try {
    payload = decrypt(AES_ALGORITHM, aes_iv, aes_key, payload_encrypted);
  } catch {
    throw new Error("Decrypt error.");
  }
  const message_key_check = sha256(Buffer.concat([
    payload,
    key_right
  ]));
  if (message_key_check.equals(message_key) !== true) {
    throw new Error("Decrypt error.");
  }
  return payload.subarray(payload[0] + 1);
}

// dist/esm/versions/v2.js
var exports_v2 = {};
__export(exports_v2, {
  encrypt: () => encrypt3,
  decrypt: () => decrypt3
});
var import_node_crypto6 = require("node:crypto");
var VERSION_ID_BUFFER2 = Buffer.from([2]);
var AES_ALGORITHM2 = "aes-256-cbc";
var PBKDF2_ITERATIONS2 = 1e5;
var PBKDF2_MESSAGE_KEY_LENGTH = 12;
var PBKDF2_AES_KEY_LENGTH = 64;
var PBKDF2_DIGEST2 = "sha256";
function getMessageKey(payload, key_right) {
  return pbkdf2(payload, key_right, PBKDF2_ITERATIONS2, PBKDF2_MESSAGE_KEY_LENGTH, PBKDF2_DIGEST2);
}
async function getAesArguments2(key_left, message_key) {
  const derived = await pbkdf2(key_left, message_key, PBKDF2_ITERATIONS2, PBKDF2_AES_KEY_LENGTH, PBKDF2_DIGEST2);
  return {
    aes_iv: derived.subarray(0, 16),
    aes_key: derived.subarray(32)
  };
}
async function encrypt3(message, key) {
  if (key.byteLength !== 64) {
    throw new Error("Key must be 64 bytes.");
  }
  const padding_bytes_meta = import_node_crypto6.randomBytes(1);
  const padding_additional_bytes_count = padding_bytes_meta[0] >>> 6;
  const payload = Buffer.concat([
    padding_bytes_meta,
    import_node_crypto6.randomBytes(4 + padding_additional_bytes_count),
    message
  ]);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const message_key = await getMessageKey(payload, key_right);
  const { aes_iv, aes_key } = await getAesArguments2(key_left, message_key);
  let payload_encrypted;
  try {
    payload_encrypted = encrypt(AES_ALGORITHM2, aes_iv, aes_key, payload);
  } catch {
    throw new Error("Encrypt error.");
  }
  return Buffer.concat([
    VERSION_ID_BUFFER2,
    message_key,
    payload_encrypted
  ]);
}
async function decrypt3(message_encrypted, key) {
  if (key.byteLength !== 64) {
    throw new Error("Key must be 64 bytes.");
  }
  const message_key = message_encrypted.subarray(1, PBKDF2_MESSAGE_KEY_LENGTH + 1);
  const payload_encrypted = message_encrypted.subarray(PBKDF2_MESSAGE_KEY_LENGTH + 1);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const { aes_iv, aes_key } = await getAesArguments2(key_left, message_key);
  let payload;
  try {
    payload = decrypt(AES_ALGORITHM2, aes_iv, aes_key, payload_encrypted);
  } catch {
    throw new Error("Decrypt error.");
  }
  const message_key_check = await getMessageKey(payload, key_right);
  if (message_key_check.equals(message_key) !== true) {
    throw new Error("Decrypt error.");
  }
  return payload.subarray(4 + (payload[0] >>> 6) + 1);
}

// dist/esm/main.js
var VERSIONS = {
  1: exports_v1,
  2: exports_v2
};
function encrypt4(message, key) {
  return encrypt2(message, key);
}
function decrypt4(message_encrypted, key) {
  const evilcrypt_version_id = message_encrypted[0];
  const version = VERSIONS[evilcrypt_version_id];
  if (!version) {
    return Promise.reject(new Error(`Unknown evilcrypt version: ${evilcrypt_version_id}.`));
  }
  return version.decrypt(message_encrypted, key);
}
