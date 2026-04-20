import { describe, it, expect } from 'vitest'
import { openKeystore, type Keystore } from '../src/keys.js'
import { WrongPassphraseError } from '../src/errors.js'

const { subtle } = globalThis.crypto

/** Build a test keystore with low PBKDF2 iterations for speed. */
async function makeKeystore(passphrase: string, iterations = 1000): Promise<Keystore> {
  const enc = new TextEncoder()
  const vaultKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16))

  const pbkdf = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey'])
  const wk = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    pbkdf,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey'],
  )
  const wrapped = await subtle.wrapKey('raw', vaultKey, wk, 'AES-KW')
  const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)))

  return {
    version: 1,
    kdf: 'PBKDF2',
    kdfParams: { hash: 'SHA-256', iterations, salt: b64(salt) },
    wrappedKey: b64(wrapped),
  }
}

describe('openKeystore', () => {
  it('returns an AES-GCM CryptoKey for the correct passphrase', async () => {
    const ks = await makeKeystore('correct-horse-battery-staple')
    const key = await openKeystore('correct-horse-battery-staple', ks)
    expect(key.type).toBe('secret')
    expect(key.algorithm.name).toBe('AES-GCM')
    expect(key.extractable).toBe(true)  // must be extractable for HKDF derivation
  })

  it('throws WrongPassphraseError for the wrong passphrase', async () => {
    const ks = await makeKeystore('correct-passphrase')
    await expect(openKeystore('wrong-passphrase', ks)).rejects.toThrow(WrongPassphraseError)
  })

  it('throws WrongPassphraseError for an empty passphrase when key was set with non-empty', async () => {
    const ks = await makeKeystore('my-secret')
    await expect(openKeystore('', ks)).rejects.toThrow(WrongPassphraseError)
  })

  it('unmarshals the same vault key each time (deterministic)', async () => {
    const ks = await makeKeystore('stable-passphrase')
    const k1 = await openKeystore('stable-passphrase', ks)
    const k2 = await openKeystore('stable-passphrase', ks)
    // Verify both keys are the same by encrypting with one and decrypting with the other
    const { encryptBytes, decryptBytes } = await import('../src/crypto.js')
    const plain = new TextEncoder().encode('roundtrip')
    const enc = await encryptBytes(k1, plain)
    await expect(decryptBytes(k2, enc)).resolves.toEqual(plain)
  })
})
