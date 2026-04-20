import { describe, it, expect } from 'vitest'
import {
  emptyManifest,
  addEntry,
  removeEntry,
  findEntry,
  encryptManifest,
  decryptManifest,
  type ManifestEntry,
} from '../src/manifest.js'
import { generateVaultKey } from '../src/crypto.js'
import { VaultCorruptError } from '../src/errors.js'

const entry1: ManifestEntry = {
  id: 'uuid-001',
  name: 'hello.txt',
  contentType: 'text/plain',
  createdAt: '2026-01-01T00:00:00Z',
  size: 5,
}

const entry2: ManifestEntry = {
  id: 'uuid-002',
  name: 'photo.jpg',
  contentType: 'image/jpeg',
  createdAt: '2026-01-02T00:00:00Z',
}

describe('manifest helpers', () => {
  it('starts empty', () => {
    expect(emptyManifest().entries).toHaveLength(0)
  })

  it('adds entries', () => {
    const m = addEntry(addEntry(emptyManifest(), entry1), entry2)
    expect(m.entries).toHaveLength(2)
  })

  it('replaces an entry with the same name', () => {
    const updated = { ...entry1, id: 'uuid-updated', size: 99 }
    const m = addEntry(addEntry(emptyManifest(), entry1), updated)
    expect(m.entries).toHaveLength(1)
    expect(m.entries[0].id).toBe('uuid-updated')
    expect(m.entries[0].size).toBe(99)
  })

  it('removes an entry by name', () => {
    const m = removeEntry(addEntry(addEntry(emptyManifest(), entry1), entry2), 'hello.txt')
    expect(m.entries).toHaveLength(1)
    expect(m.entries[0].name).toBe('photo.jpg')
  })

  it('remove is a no-op for unknown names', () => {
    const m = addEntry(emptyManifest(), entry1)
    expect(removeEntry(m, 'nonexistent.txt').entries).toHaveLength(1)
  })

  it('finds an entry by name', () => {
    const m = addEntry(emptyManifest(), entry1)
    expect(findEntry(m, 'hello.txt')).toEqual(entry1)
    expect(findEntry(m, 'missing.txt')).toBeUndefined()
  })
})

describe('encryptManifest / decryptManifest', () => {
  it('round-trips a manifest', async () => {
    const key = await generateVaultKey()
    const m = addEntry(addEntry(emptyManifest(), entry1), entry2)
    const enc = await encryptManifest(key, m)
    const dec = await decryptManifest(key, enc)
    expect(dec.version).toBe(1)
    expect(dec.entries).toHaveLength(2)
    expect(dec.entries[0]).toEqual(entry1)
    expect(dec.entries[1]).toEqual(entry2)
  })

  it('round-trips an empty manifest', async () => {
    const key = await generateVaultKey()
    const enc = await encryptManifest(key, emptyManifest())
    const dec = await decryptManifest(key, enc)
    expect(dec.entries).toHaveLength(0)
  })

  it('throws VaultCorruptError when decrypting with the wrong key', async () => {
    const key1 = await generateVaultKey()
    const key2 = await generateVaultKey()
    const enc = await encryptManifest(key1, emptyManifest())
    await expect(decryptManifest(key2, enc)).rejects.toThrow(VaultCorruptError)
  })

  it('throws VaultCorruptError when ciphertext is corrupted', async () => {
    const key = await generateVaultKey()
    const enc = await encryptManifest(key, emptyManifest())
    enc[20] ^= 0xff
    await expect(decryptManifest(key, enc)).rejects.toThrow(VaultCorruptError)
  })
})
