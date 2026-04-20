import { WrongPassphraseError } from './errors.js'

const { subtle } = globalThis.crypto

/** Coerce Uint8Array to plain ArrayBuffer for WebCrypto (TypeScript 5.7+ requires this). */
function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer
}

/** Shape of the keystore stored at /vault/.keystore in the pod. */
export interface Keystore {
  version: number
  kdf: string
  kdfParams: {
    hash: string
    iterations: number
    salt: string   // base64-encoded 16-byte salt
  }
  wrappedKey: string           // base64 — vault key wrapped with passphrase-derived AES-KW key
  recoveryWrappedKey?: string  // base64 — vault key wrapped with random recovery key (if present)
}

function b64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

/**
 * Unwrap the vault key from a keystore using the user's passphrase.
 * Throws WrongPassphraseError if the passphrase is incorrect.
 */
export async function openKeystore(passphrase: string, keystore: Keystore): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const salt = b64ToBytes(keystore.kdfParams.salt)
  const wrappedKeyBytes = b64ToBytes(keystore.wrappedKey)

  const pbkdfMaterial = await subtle.importKey(
    'raw', ab(enc.encode(passphrase)), 'PBKDF2', false, ['deriveKey'],
  )
  const unwrappingKey = await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: ab(salt),
      iterations: keystore.kdfParams.iterations,
      hash: keystore.kdfParams.hash,
    },
    pbkdfMaterial,
    { name: 'AES-KW', length: 256 },
    false,
    ['unwrapKey'],
  )

  try {
    return await subtle.unwrapKey(
      'raw',
      ab(wrappedKeyBytes),
      unwrappingKey,
      'AES-KW',
      { name: 'AES-GCM', length: 256 },
      true,   // extractable — needed so we can re-export for HKDF in deriveAppKey
      ['encrypt', 'decrypt'],
    )
  } catch {
    throw new WrongPassphraseError()
  }
}
