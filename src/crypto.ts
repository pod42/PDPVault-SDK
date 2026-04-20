// Pure WebCrypto — works in browser and Node 18+

const { subtle } = globalThis.crypto

/** Coerce Uint8Array to a plain ArrayBuffer for WebCrypto (TypeScript 5.7+ requires this). */
function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer
}

/** Generate a new AES-256-GCM vault key. */
export async function generateVaultKey(): Promise<CryptoKey> {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
}

/**
 * Derive a per-app AES-256-GCM key from the vault key using HKDF.
 * Different appNamespace values produce independent keys, so apps
 * cannot read each other's encrypted files even sharing a vault.
 */
export async function deriveAppKey(vaultKey: CryptoKey, appNamespace: string): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const rawVaultKey = await subtle.exportKey('raw', vaultKey)
  const hkdfMaterial = await subtle.importKey('raw', rawVaultKey as ArrayBuffer, 'HKDF', false, ['deriveKey'])
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: ab(enc.encode('privatedatapod-vault-v1')),
      info: ab(enc.encode(appNamespace)),
    },
    hkdfMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns a Uint8Array with the 12-byte IV prepended to the ciphertext.
 */
export async function encryptBytes(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, ab(plaintext))
  const result = new Uint8Array(12 + ciphertext.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(ciphertext), 12)
  return result
}

/**
 * Decrypt data produced by encryptBytes.
 * Expects the 12-byte IV prepended to the ciphertext.
 */
export async function decryptBytes(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const iv = data.slice(0, 12)
  const ciphertext = data.slice(12)
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ab(ciphertext))
  return new Uint8Array(plaintext)
}
