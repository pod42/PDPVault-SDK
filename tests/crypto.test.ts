import { describe, it, expect } from 'vitest'
import { generateVaultKey, deriveAppKey, encryptBytes, decryptBytes } from '../src/crypto.js'

describe('generateVaultKey', () => {
  it('produces an extractable AES-256-GCM key', async () => {
    const key = await generateVaultKey()
    expect(key.type).toBe('secret')
    expect(key.algorithm.name).toBe('AES-GCM')
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256)
    expect(key.extractable).toBe(true)
  })
})

describe('encryptBytes / decryptBytes', () => {
  it('round-trips plaintext', async () => {
    const key = await generateVaultKey()
    const plain = new TextEncoder().encode('Hello, vault!')
    const enc = await encryptBytes(key, plain)
    const dec = await decryptBytes(key, enc)
    expect(dec).toEqual(plain)
  })

  it('produces different ciphertext each call (random IV)', async () => {
    const key = await generateVaultKey()
    const plain = new TextEncoder().encode('same plaintext')
    const enc1 = await encryptBytes(key, plain)
    const enc2 = await encryptBytes(key, plain)
    expect(enc1).not.toEqual(enc2)
  })

  it('throws when ciphertext is tampered', async () => {
    const key = await generateVaultKey()
    const enc = await encryptBytes(key, new TextEncoder().encode('secret'))
    enc[20] ^= 0xff  // flip a byte in the ciphertext
    await expect(decryptBytes(key, enc)).rejects.toThrow()
  })
})

describe('deriveAppKey', () => {
  it('derives different keys for different namespaces', async () => {
    const vaultKey = await generateVaultKey()
    const k1 = await deriveAppKey(vaultKey, 'drive')
    const k2 = await deriveAppKey(vaultKey, 'notes')
    const plain = new TextEncoder().encode('test data')
    // Each key encrypts/decrypts its own data
    const c1 = await encryptBytes(k1, plain)
    const c2 = await encryptBytes(k2, plain)
    await expect(decryptBytes(k1, c1)).resolves.toEqual(plain)
    await expect(decryptBytes(k2, c2)).resolves.toEqual(plain)
    // Cross-decrypt should fail (wrong key)
    await expect(decryptBytes(k2, c1)).rejects.toThrow()
    await expect(decryptBytes(k1, c2)).rejects.toThrow()
  })

  it('produces the same key deterministically for the same inputs', async () => {
    const vaultKey = await generateVaultKey()
    const k1 = await deriveAppKey(vaultKey, 'drive')
    const k2 = await deriveAppKey(vaultKey, 'drive')
    const plain = new TextEncoder().encode('deterministic')
    const enc = await encryptBytes(k1, plain)
    await expect(decryptBytes(k2, enc)).resolves.toEqual(plain)
  })
})
