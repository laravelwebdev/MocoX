/**
 * Decodes a key from either base64 or hex encoding.
 * Tries base64 first; if the decoded length is not 16 or 32 bytes,
 * falls back to hex decoding for 32-char (16-byte) or 64-char (32-byte) inputs.
 *
 * @param {string} temporaryKey - base64 or hex encoded AES key
 * @returns {Uint8Array} - 16 or 32 byte key
 */
function decodeKey(temporaryKey) {
  // Try base64 decode first
  try {
    const raw = atob(temporaryKey);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    if (bytes.length === 16 || bytes.length === 32) {
      return bytes;
    }
  } catch (_) {
    // base64 decode failed, fall through to hex
  }

  // Try hex decode
  if (temporaryKey.length === 32 || temporaryKey.length === 64) {
    const bytes = new Uint8Array(temporaryKey.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(temporaryKey.slice(i * 2, i * 2 + 2), 16);
    }
    if (bytes.length === 16 || bytes.length === 32) {
      return bytes;
    }
  }

  throw new Error("Invalid key: must decode to 16 or 32 bytes");
}

/**
 * Decrypts an AES-CBC encrypted password.
 * The encrypted data is base64-encoded; the first 16 bytes of the decoded
 * data are the IV and the remaining bytes are the ciphertext.
 *
 * @param {string} encryptedPass - base64-encoded IV + ciphertext
 * @param {string} temporaryKey - base64 or hex encoded AES key
 * @returns {Promise<string>} - decrypted password
 */
async function decryptPassword(encryptedPass, temporaryKey) {
  const keyBytes = decodeKey(temporaryKey);

  const rawEncrypted = atob(encryptedPass);
  const rawBytes = new Uint8Array(rawEncrypted.length);
  for (let i = 0; i < rawEncrypted.length; i++) {
    rawBytes[i] = rawEncrypted.charCodeAt(i);
  }

  if (rawBytes.length < 32) {
    throw new Error("Encrypted data must be at least 32 bytes (16-byte IV + 16-byte minimum ciphertext)");
  }

  const iv = rawBytes.slice(0, 16);
  const ciphertext = rawBytes.slice(16);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

/**
 * Retrieves the ZIP file password by decrypting the re-encrypted ZIP password.
 *
 * @param {string} reencryptedZipPass - base64-encoded IV + AES-CBC ciphertext of the ZIP password
 * @param {string} temporaryKey - base64 or hex encoded AES key
 * @returns {Promise<string>} - decrypted ZIP password
 */
async function getZipPassword(reencryptedZipPass, temporaryKey) {
  return decryptPassword(reencryptedZipPass, temporaryKey);
}

/**
 * Retrieves the ODF file password by decrypting the re-encrypted ODF password.
 *
 * @param {string} reencryptedOdfPass - base64-encoded IV + AES-CBC ciphertext of the ODF password
 * @param {string} temporaryKey - base64 or hex encoded AES key
 * @returns {Promise<string>} - decrypted ODF password
 */
async function getOdfPassword(reencryptedOdfPass, temporaryKey) {
  return decryptPassword(reencryptedOdfPass, temporaryKey);
}
