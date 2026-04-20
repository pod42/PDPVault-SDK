/**
 * Key delegation: allows one app (the grantor) to grant another app (the
 * recipient) the ability to decrypt a vault namespace, without the user
 * re-entering their passphrase.
 *
 * Mechanism: ECDH-P256 key agreement + AES-KW wrapping
 *
 * Grantor side (App A, vault unlocked):
 *   1. Fetch recipient's ECDH public key from the pod.
 *   2. Generate an ephemeral ECDH keypair.
 *   3. Perform ECDH between ephemeral private key and recipient public key
 *      to derive a shared AES-256 wrapping key.
 *   4. Wrap the derived app key (AES-256-GCM) with AES-KW.
 *   5. Write a grant document to /vault/.grants/{namespace}/{thumbprint}.json
 *      containing the wrapped key and the ephemeral public key.
 *
 * Recipient side (App B):
 *   1. Generate (or load from IndexedDB) an ECDH keypair.
 *   2. Publish the public key JWK to /vault/.delegation-keys/{namespace}.json
 *      so the grantor can find it.
 *   3. On open: fetch own grant document, perform ECDH with stored private key
 *      and the ephemeral public key from the grant, derive same wrapping key,
 *      unwrap the app key.
 *
 * Security properties:
 *   - Server never sees a plaintext key at any step.
 *   - Grant is scoped to a single namespace.
 *   - Revocation: delete the grant document. For cryptographic revocation,
 *     rotate the app key (re-encrypt all files) after deletion.
 *   - The recipient's private key is non-extractable and lives in IndexedDB.
 */

const { subtle } = globalThis.crypto

// ── Type definitions ──────────────────────────────────────────────────────────

export interface GrantDocument {
  version: 1
  grantedBy: string             // WebID of the user who created the grant
  namespace: string             // vault namespace this grant covers
  algorithm: 'ECDH-P256+AES-KW-256'
  ephemeralPublicKey: JsonWebKey
  wrappedKey: string            // base64url-encoded AES-KW wrapped app key
  issuedAt: string              // ISO 8601
  expiresAt: string | null
}

export interface DelegationPublicKeyDocument {
  publicKeyJwk: JsonWebKey
  thumbprint: string            // RFC 7638 JWK thumbprint (base64url SHA-256)
  deviceName?: string           // Human-readable device label (e.g. "iPhone (Safari)")
}

// ── IndexedDB helpers ─────────────────────────────────────────────────────────

const IDB_NAME = 'pdp-vault-delegation'
const IDB_STORE = 'keys'
const IDB_VERSION = 1

function openIdb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION)
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openIdb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readonly')
    const req = tx.objectStore(IDB_STORE).get(key)
    req.onsuccess = () => { db.close(); resolve(req.result as T | undefined) }
    req.onerror = () => { db.close(); reject(req.error) }
  })
}

async function idbPut(key: string, value: unknown): Promise<void> {
  const db = await openIdb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readwrite')
    const req = tx.objectStore(IDB_STORE).put(value, key)
    req.onsuccess = () => { db.close(); resolve() }
    req.onerror = () => { db.close(); reject(req.error) }
  })
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

function toBase64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function fromBase64url(s: string): Uint8Array {
  return Uint8Array.from(
    atob(s.replace(/-/g, '+').replace(/_/g, '/')),
    c => c.charCodeAt(0),
  )
}

/** Coerce Uint8Array to ArrayBuffer for TS 5.7+ WebCrypto compatibility. */
function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer
}

// ── RFC 7638 JWK thumbprint ───────────────────────────────────────────────────

/** Compute the RFC 7638 thumbprint of an EC P-256 public key JWK. */
export async function computeThumbprint(jwk: JsonWebKey): Promise<string> {
  // Canonical form: lexicographically sorted required members for EC keys
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  const hash = await subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return toBase64url(new Uint8Array(hash))
}

// ── Delegation keypair management ─────────────────────────────────────────────

/**
 * Get the delegation ECDH keypair for a namespace from IndexedDB, generating
 * one if it does not yet exist. The private key is stored non-extractable.
 * Returns the public key JWK and thumbprint for publishing.
 */
export async function getOrCreateDelegationKeyPair(namespace: string): Promise<{
  publicKeyJwk: JsonWebKey
  thumbprint: string
  privateKey: CryptoKey
}> {
  const privateStoreKey = `priv-${namespace}`
  const metaStoreKey = `meta-${namespace}`

  const existingPrivate = await idbGet<CryptoKey>(privateStoreKey)
  const existingMeta = await idbGet<{ publicKeyJwk: JsonWebKey; thumbprint: string }>(metaStoreKey)

  if (existingPrivate && existingMeta) {
    return { ...existingMeta, privateKey: existingPrivate }
  }

  // Generate a fresh ECDH P-256 keypair.
  // Use extractable: true so we can export the public key; the private key
  // is stored in IndexedDB and never exported by SDK code.
  const pair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  )

  const publicKeyJwk = await subtle.exportKey('jwk', pair.publicKey)
  const thumbprint = await computeThumbprint(publicKeyJwk)

  // Store private key and metadata
  await idbPut(privateStoreKey, pair.privateKey)
  await idbPut(metaStoreKey, { publicKeyJwk, thumbprint })

  return { publicKeyJwk, thumbprint, privateKey: pair.privateKey }
}

/**
 * Publish the delegation public key to the pod at
 * /vault/.delegation-keys/{namespace}/{thumbprint}.json
 * Each device/browser gets its own file keyed by thumbprint, so multiple
 * devices can register independently without overwriting each other.
 * Returns the URL where it was written.
 */
export async function publishDelegationPublicKey(
  f: typeof globalThis.fetch,
  podUrl: string,
  namespace: string,
  publicKeyJwk: JsonWebKey,
  thumbprint: string,
  deviceName?: string,
): Promise<string> {
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  // Ensure vault/.delegation-keys/ container exists
  const rootContainerUrl = `${base}vault/.delegation-keys/`
  const rootHead = await f(rootContainerUrl, { method: 'HEAD' })
  if (!rootHead.ok) {
    const ttl = '@prefix ldp: <http://www.w3.org/ns/ldp#>.\n<> a ldp:BasicContainer .\n'
    await f(rootContainerUrl, { method: 'PUT', headers: { 'Content-Type': 'text/turtle' }, body: ttl })
  }
  // Ensure vault/.delegation-keys/{namespace}/ container exists
  const nsContainerUrl = `${base}vault/.delegation-keys/${namespace}/`
  const nsHead = await f(nsContainerUrl, { method: 'HEAD' })
  if (!nsHead.ok) {
    const ttl = '@prefix ldp: <http://www.w3.org/ns/ldp#>.\n<> a ldp:BasicContainer .\n'
    await f(nsContainerUrl, { method: 'PUT', headers: { 'Content-Type': 'text/turtle' }, body: ttl })
  }

  const keyUrl = `${base}vault/.delegation-keys/${namespace}/${thumbprint}.json`
  const doc: DelegationPublicKeyDocument = deviceName
    ? { publicKeyJwk, thumbprint, deviceName }
    : { publicKeyJwk, thumbprint }
  const r = await f(keyUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(doc),
  })
  if (!r.ok) throw new Error(`Could not publish delegation key: HTTP ${r.status}`)
  return keyUrl
}

/** Return the URL of the delegation public key document for a namespace + thumbprint. */
export function delegationKeyUrl(podUrl: string, namespace: string, thumbprint: string): string {
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  return `${base}vault/.delegation-keys/${namespace}/${thumbprint}.json`
}

/** Return the URL of a grant document for a namespace + recipient thumbprint. */
export function grantUrl(podUrl: string, namespace: string, thumbprint: string): string {
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  return `${base}vault/.grants/${namespace}/${thumbprint}.json`
}

// ── Grant creation (grantor / App A side) ─────────────────────────────────────

/**
 * Wrap an app key for a recipient and write the grant document to the pod.
 * The grantor must have the vault unlocked (appKey in memory).
 *
 * @param f - Authenticated fetch
 * @param podUrl - Pod root URL
 * @param namespace - Namespace to grant
 * @param appKey - The derived app key (AES-256-GCM) to wrap
 * @param granterWebId - WebID of the user creating the grant
 * @param recipientPublicJwk - Recipient's ECDH public key JWK
 * @param recipientThumbprint - RFC 7638 thumbprint of recipient's public key
 * @param expiresAt - Optional expiry; null means no expiry
 */
export async function createAndWriteGrant(
  f: typeof globalThis.fetch,
  podUrl: string,
  namespace: string,
  appKey: CryptoKey,
  granterWebId: string,
  recipientPublicJwk: JsonWebKey,
  recipientThumbprint: string,
  expiresAt: Date | null,
): Promise<void> {
  // Import recipient's public key for ECDH
  const recipientPublicKey = await subtle.importKey(
    'jwk',
    recipientPublicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )

  // Generate an ephemeral ECDH keypair for this grant
  const ephemeral = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  )

  // ECDH: ephemeral private + recipient public -> shared AES-256 wrapping key
  const wrappingKey = await subtle.deriveKey(
    { name: 'ECDH', public: recipientPublicKey },
    ephemeral.privateKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey'],
  )

  // Wrap the app key with AES-KW
  const wrappedKeyBuffer = await subtle.wrapKey('raw', appKey, wrappingKey, 'AES-KW')
  const wrappedKey = toBase64url(new Uint8Array(wrappedKeyBuffer))

  const ephemeralPublicKey = await subtle.exportKey('jwk', ephemeral.publicKey)

  const grant: GrantDocument = {
    version: 1,
    grantedBy: granterWebId,
    namespace,
    algorithm: 'ECDH-P256+AES-KW-256',
    ephemeralPublicKey,
    wrappedKey,
    issuedAt: new Date().toISOString(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  }

  // Ensure the grants container hierarchy exists
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  const grantsRootUrl = `${base}vault/.grants/`
  const nsGrantsUrl = `${grantsRootUrl}${namespace}/`

  for (const containerUrl of [grantsRootUrl, nsGrantsUrl]) {
    const head = await f(containerUrl, { method: 'HEAD' })
    if (!head.ok) {
      const ttl = '@prefix ldp: <http://www.w3.org/ns/ldp#>.\n<> a ldp:BasicContainer .\n'
      await f(containerUrl, { method: 'PUT', headers: { 'Content-Type': 'text/turtle' }, body: ttl })
    }
  }

  const url = grantUrl(podUrl, namespace, recipientThumbprint)
  const r = await f(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(grant),
  })
  if (!r.ok) throw new Error(`Could not write delegation grant: HTTP ${r.status}`)
}

// ── Grant consumption (recipient / App B side) ────────────────────────────────

/**
 * Try to open a vault namespace using a delegation grant.
 * Looks up this app's delegation keypair in IndexedDB, fetches the
 * corresponding grant from the pod, and unwraps the app key.
 *
 * Returns the unwrapped app CryptoKey, or null if no grant exists.
 */
export async function tryOpenWithGrant(
  f: typeof globalThis.fetch,
  podUrl: string,
  namespace: string,
): Promise<CryptoKey | null> {
  // No IndexedDB in non-browser environments
  if (typeof indexedDB === 'undefined') return null

  const privateStoreKey = `priv-${namespace}`
  const metaStoreKey = `meta-${namespace}`

  const privateKey = await idbGet<CryptoKey>(privateStoreKey)
  const meta = await idbGet<{ publicKeyJwk: JsonWebKey; thumbprint: string }>(metaStoreKey)
  if (!privateKey || !meta) return null

  const url = grantUrl(podUrl, namespace, meta.thumbprint)
  const r = await f(url)
  if (!r.ok) return null  // no grant yet, or revoked

  const grant = await r.json() as GrantDocument

  // Check expiry
  if (grant.expiresAt && new Date(grant.expiresAt) < new Date()) return null

  return unwrapGrantKey(grant, privateKey)
}

/**
 * Unwrap the app key from a grant document using the recipient's private key.
 */
export async function unwrapGrantKey(
  grant: GrantDocument,
  recipientPrivateKey: CryptoKey,
): Promise<CryptoKey> {
  // Import the ephemeral public key from the grant
  const ephemeralPublicKey = await subtle.importKey(
    'jwk',
    grant.ephemeralPublicKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )

  // ECDH: recipient private + ephemeral public -> same shared wrapping key
  const wrappingKey = await subtle.deriveKey(
    { name: 'ECDH', public: ephemeralPublicKey },
    recipientPrivateKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['unwrapKey'],
  )

  const wrappedKeyBytes = ab(fromBase64url(grant.wrappedKey))

  // Unwrap the AES-256-GCM app key
  return subtle.unwrapKey(
    'raw',
    wrappedKeyBytes,
    wrappingKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}
