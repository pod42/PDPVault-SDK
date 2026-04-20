import { encryptBytes, decryptBytes } from './crypto.js'
import { VaultCorruptError } from './errors.js'

/** A single file tracked in the encrypted manifest. */
export interface ManifestEntry {
  /** Opaque server-side filename (random UUID). Never exposed to users. */
  id: string
  /** Logical filename as provided by the app (e.g. "my-document.txt"). */
  name: string
  /** MIME type of the original plaintext content. */
  contentType: string
  /** ISO 8601 creation timestamp. */
  createdAt: string
  /** Byte size of the plaintext content. */
  size?: number
}

export interface Manifest {
  version: 1
  entries: ManifestEntry[]
}

export function emptyManifest(): Manifest {
  return { version: 1, entries: [] }
}

/** Encrypt a manifest with the given AES-256-GCM key. */
export async function encryptManifest(key: CryptoKey, manifest: Manifest): Promise<Uint8Array> {
  const enc = new TextEncoder()
  return encryptBytes(key, enc.encode(JSON.stringify(manifest)))
}

/** Decrypt a manifest. Throws VaultCorruptError if the data cannot be decrypted or parsed. */
export async function decryptManifest(key: CryptoKey, data: Uint8Array): Promise<Manifest> {
  const dec = new TextDecoder()
  try {
    const plain = await decryptBytes(key, data)
    return JSON.parse(dec.decode(plain)) as Manifest
  } catch {
    throw new VaultCorruptError('Could not decrypt manifest')
  }
}

/**
 * Add or replace an entry by logical name.
 * If an entry with the same name exists it is overwritten.
 */
export function addEntry(manifest: Manifest, entry: ManifestEntry): Manifest {
  const entries = manifest.entries.filter(e => e.name !== entry.name)
  return { ...manifest, entries: [...entries, entry] }
}

/** Remove an entry by logical name. No-op if not found. */
export function removeEntry(manifest: Manifest, name: string): Manifest {
  return { ...manifest, entries: manifest.entries.filter(e => e.name !== name) }
}

/** Find an entry by logical name. Returns undefined if not found. */
export function findEntry(manifest: Manifest, name: string): ManifestEntry | undefined {
  return manifest.entries.find(e => e.name === name)
}
