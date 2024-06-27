var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.js
var main_exports = {};
__export(main_exports, {
  decrypt: () => decrypt4,
  encrypt: () => encrypt4,
  v1: () => v1_exports,
  v2: () => v2_exports
});
module.exports = __toCommonJS(main_exports);

// src/versions/v1.js
var v1_exports = {};
__export(v1_exports, {
  decrypt: () => decrypt2,
  encrypt: () => encrypt2
});
var import_node_crypto3 = require("node:crypto");

// src/crypto/aes.js
var crypto = __toESM(require("node:crypto"), 1);
function encrypt(algorithm, iv, key, data) {
  const cipher = crypto.createCipheriv(
    algorithm,
    key,
    iv
  );
  cipher.setAutoPadding(true);
  return Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);
}
function decrypt(algorithm, iv, key, data) {
  const decipher = crypto.createDecipheriv(
    algorithm,
    key,
    iv
  );
  decipher.setAutoPadding(true);
  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}

// src/crypto/pbkdf2.js
var import_node_crypto = require("node:crypto");
async function pbkdf2(secret, salt, iterations, key_length, digest = "sha256") {
  return new Promise((resolve, reject) => {
    (0, import_node_crypto.pbkdf2)(
      secret,
      salt,
      iterations,
      key_length,
      digest,
      (error, derived_key) => {
        if (error) {
          reject(error);
        } else {
          resolve(derived_key);
        }
      }
    );
  });
}

// src/crypto/sha.js
var crypto2 = __toESM(require("node:crypto"), 1);
function sha256(buffer) {
  return crypto2.createHash("sha256").update(buffer).digest();
}

// src/utils/random.js
var import_node_crypto2 = require("node:crypto");
var RANDOM_NUMBER_LIMIT = 4294967296;
function randomInt(min_incl, max_not_incl) {
  const buffer = (0, import_node_crypto2.randomBytes)(4);
  const max_from_zero = max_not_incl - min_incl;
  const number = (buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3]) >>> 0;
  const number_max = RANDOM_NUMBER_LIMIT - RANDOM_NUMBER_LIMIT % max_from_zero - 1;
  if (number > number_max) {
    return randomInt(min_incl, max_not_incl);
  }
  return min_incl + number % max_from_zero;
}

// src/versions/v1.js
var VERSION_ID_BUFFER = Buffer.from([1]);
var AES_ALGORITHM = "aes-256-cbc";
var PBKDF2_ITERATIONS = 1e5;
var PBKDF2_KEY_LENGTH = 64;
var PBKDF2_DIGEST = "sha256";
async function getAesArguments(key_left, message_key) {
  const derived = await pbkdf2(
    key_left,
    message_key,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LENGTH,
    PBKDF2_DIGEST
  );
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
  const padding_length = randomInt(
    8,
    Math.min(
      Math.round(message_length * 0.4) + 12,
      256
    )
  );
  const padding = (0, import_node_crypto3.randomBytes)(padding_length);
  const payload = Buffer.concat([
    Buffer.from([
      padding_length
    ]),
    padding,
    message
  ]);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const message_key = sha256(
    Buffer.concat([
      payload,
      key_right
    ])
  );
  const {
    aes_iv,
    aes_key
  } = await getAesArguments(key_left, message_key);
  let payload_encrypted;
  try {
    payload_encrypted = encrypt(
      AES_ALGORITHM,
      aes_iv,
      aes_key,
      payload
    );
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
    payload = decrypt(
      AES_ALGORITHM,
      aes_iv,
      aes_key,
      payload_encrypted
    );
  } catch {
    throw new Error("Decrypt error.");
  }
  const message_key_check = sha256(
    Buffer.concat([
      payload,
      key_right
    ])
  );
  if (message_key_check.equals(message_key) !== true) {
    throw new Error("Decrypt error.");
  }
  return payload.subarray(
    payload[0] + 1
  );
}

// src/versions/v2.js
var v2_exports = {};
__export(v2_exports, {
  decrypt: () => decrypt3,
  encrypt: () => encrypt3
});
var import_node_crypto4 = require("node:crypto");
var VERSION_ID_BUFFER2 = Buffer.from([2]);
var AES_ALGORITHM2 = "aes-256-cbc";
var PBKDF2_ITERATIONS2 = 1e5;
var PBKDF2_MESSAGE_KEY_LENGTH = 12;
var PBKDF2_AES_KEY_LENGTH = 64;
var PBKDF2_DIGEST2 = "sha256";
function getMessageKey(payload, key_right) {
  return pbkdf2(
    payload,
    key_right,
    PBKDF2_ITERATIONS2,
    PBKDF2_MESSAGE_KEY_LENGTH,
    PBKDF2_DIGEST2
  );
}
async function getAesArguments2(key_left, message_key) {
  const derived = await pbkdf2(
    key_left,
    message_key,
    PBKDF2_ITERATIONS2,
    PBKDF2_AES_KEY_LENGTH,
    PBKDF2_DIGEST2
  );
  return {
    aes_iv: derived.subarray(0, 16),
    aes_key: derived.subarray(32)
  };
}
async function encrypt3(message, key) {
  if (key.byteLength !== 64) {
    throw new Error("Key must be 64 bytes.");
  }
  const padding_bytes_meta = (0, import_node_crypto4.randomBytes)(1);
  const padding_additional_bytes_count = padding_bytes_meta[0] >>> 6;
  const payload = Buffer.concat([
    padding_bytes_meta,
    (0, import_node_crypto4.randomBytes)(4 + padding_additional_bytes_count),
    message
  ]);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const message_key = await getMessageKey(payload, key_right);
  const { aes_iv, aes_key } = await getAesArguments2(key_left, message_key);
  let payload_encrypted;
  try {
    payload_encrypted = encrypt(
      AES_ALGORITHM2,
      aes_iv,
      aes_key,
      payload
    );
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
  const message_key = message_encrypted.subarray(
    1,
    PBKDF2_MESSAGE_KEY_LENGTH + 1
  );
  const payload_encrypted = message_encrypted.subarray(PBKDF2_MESSAGE_KEY_LENGTH + 1);
  const key_left = key.subarray(0, 32);
  const key_right = key.subarray(32);
  const { aes_iv, aes_key } = await getAesArguments2(key_left, message_key);
  let payload;
  try {
    payload = decrypt(
      AES_ALGORITHM2,
      aes_iv,
      aes_key,
      payload_encrypted
    );
  } catch {
    throw new Error("Decrypt error.");
  }
  const message_key_check = await getMessageKey(payload, key_right);
  if (message_key_check.equals(message_key) !== true) {
    throw new Error("Decrypt error.");
  }
  return payload.subarray(
    4 + (payload[0] >>> 6) + 1
    // eslint-disable-line no-bitwise
  );
}

// src/main.js
var VERSIONS = {
  1: v1_exports,
  2: v2_exports
};
async function encrypt4(message, key) {
  return encrypt2(message, key);
}
async function decrypt4(message_encrypted, key) {
  const evilcrypt_version_id = message_encrypted[0];
  const version = VERSIONS[evilcrypt_version_id];
  if (!version) {
    throw new Error(`Unknown evilcrypt version: ${evilcrypt_version_id}.`);
  }
  return version.decrypt(
    message_encrypted,
    key
  );
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  decrypt,
  encrypt,
  v1,
  v2
});
