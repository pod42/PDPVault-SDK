import { openKeystore, type Keystore } from './keys.js'
import { deriveAppKey, encryptBytes, decryptBytes } from './crypto.js'
import {
  type Manifest,
  type ManifestEntry,
  encryptManifest,
  decryptManifest,
  addEntry,
  removeEntry,
  findEntry,
  emptyManifest,
} from './manifest.js'
import {
  VaultNotFoundError,
  VaultLockedError,
  VaultAccessDeniedError,
  VaultCorruptError,
} from './errors.js'
import { writeSidecar } from './sidecar.js'
import {
  tryOpenWithGrant,
  getOrCreateDelegationKeyPair,
  publishDelegationPublicKey,
  createAndWriteGrant,
  type DelegationPublicKeyDocument,
} from './delegation.js'

export interface PodStorageOptions {
  /** Full URL of the user's pod root, e.g. "https://alice.privatedatapod.com/". */
  podUrl: string
  /**
   * Authenticated fetch function (e.g. from @inrupt/solid-client-authn-browser).
   * Falls back to globalThis.fetch if omitted.
   */
  fetch?: typeof globalThis.fetch
  /**
   * Namespace string that scopes this storage to your app.
   * Used as the directory name inside /vault/ and as HKDF input — so two apps
   * with different namespaces cannot decrypt each other's files.
   * Use a short stable identifier, e.g. "drive", "notes", "photos".
   */
  appNamespace: string
  /**
   * Callback invoked when the vault keystore is found and a passphrase is required.
   * Return the passphrase string. Throw to cancel the open.
   * Optional when `delegation: true` and a valid grant exists — delegation
   * is tried first and the passphrase callback is only called if no grant is found.
   */
  onNeedPassphrase?: () => Promise<string>
  /**
   * When true, maintain an owner-only RDF sidecar index at
   * /vault/.index.{namespace}.ttl on every write. Enables Solid-standard
   * discoverability for owner agents (backup tools, search, migration).
   * Filenames are stored in plaintext in the sidecar; set to false if your
   * threat model requires zero plaintext metadata on the server.
   * Default: false
   */
  rdfIndex?: boolean
  /**
   * When true, try to open the vault using a delegation grant from IndexedDB
   * before falling back to the passphrase callback. Also enables
   * `registerDelegationKey()` and `grantAccess()` methods.
   * Default: false
   */
  delegation?: boolean
}

/**
 * PodStorage — unified encrypted/plaintext storage backed by a Solid pod.
 *
 * Usage:
 * ```ts
 * const storage = await PodStorage.open({
 *   podUrl: 'https://alice.privatedatapod.com/',
 *   fetch: session.fetch,
 *   appNamespace: 'drive',
 *   onNeedPassphrase: () => prompt('Enter vault passphrase:'),
 * })
 *
 * await storage.put('hello.txt', new TextEncoder().encode('Hello!'), 'text/plain')
 * const data = await storage.get('hello.txt')
 * const files = await storage.list()
 * await storage.delete('hello.txt')
 * storage.lock()   // clear vault key from memory
 * ```
 *
 * When a vault keystore exists at /vault/.keystore, files are stored encrypted
 * at /vault/{appNamespace}/{opaqueId} with an encrypted manifest tracking
 * logical filenames. When no keystore exists the vault is not set up and files
 * are stored as plain Solid resources at /{appNamespace}/{name}.
 */
export class PodStorage {
  /** True when operating in encrypted vault mode. */
  /** True when operating in encrypted vault mode. */
  readonly isEncrypted: boolean
  /** True when this session was opened via a delegation grant (no passphrase needed). */
  readonly isDelegated: boolean

  private readonly _fetch: typeof globalThis.fetch
  private readonly _podUrl: string
  private readonly _appNamespace: string
  private readonly _rdfIndex: boolean
  private readonly _delegation: boolean
  private _appKey: CryptoKey | null

  private constructor(opts: {
    podUrl: string
    fetch: typeof globalThis.fetch
    appNamespace: string
    isEncrypted: boolean
    isDelegated?: boolean
    appKey?: CryptoKey
    rdfIndex?: boolean
    delegation?: boolean
  }) {
    this._podUrl = opts.podUrl.endsWith('/') ? opts.podUrl : opts.podUrl + '/'
    this._fetch = opts.fetch
    this._appNamespace = opts.appNamespace
    this.isEncrypted = opts.isEncrypted
    this.isDelegated = opts.isDelegated ?? false
    this._rdfIndex = opts.rdfIndex ?? false
    this._delegation = opts.delegation ?? false
    this._appKey = opts.appKey ?? null
  }

  /**
   * Open storage for a pod.
   * - If /vault/.keystore exists → encrypted mode.
   *   - If `delegation: true`, tries a grant first (silent); falls back to onNeedPassphrase.
   *   - Otherwise calls onNeedPassphrase directly.
   * - If no keystore (404):
   *   - If `delegation: true`, tries a grant (App B may have a grant without a keystore).
   *   - Otherwise → plaintext mode.
   * - 401/403 → throws VaultAccessDeniedError.
   */
  static async open(opts: PodStorageOptions): Promise<PodStorage> {
    const f = opts.fetch ?? globalThis.fetch
    const podUrl = opts.podUrl.endsWith('/') ? opts.podUrl : opts.podUrl + '/'
    const shared = {
      fetch: f,
      appNamespace: opts.appNamespace,
      rdfIndex: opts.rdfIndex ?? false,
      delegation: opts.delegation ?? false,
    }

    const kr = await f(`${podUrl}vault/.keystore`, { headers: { Accept: 'application/json' } })

    if (kr.status === 401 || kr.status === 403) throw new VaultAccessDeniedError()

    if (kr.status === 404) {
      // No keystore on this pod — try delegation before falling back to plaintext
      if (opts.delegation) {
        const appKey = await tryOpenWithGrant(f, podUrl, opts.appNamespace)
        if (appKey) {
          return new PodStorage({ podUrl, ...shared, isEncrypted: true, isDelegated: true, appKey })
        }
      }
      return new PodStorage({ podUrl, ...shared, isEncrypted: false })
    }

    if (!kr.ok) throw new VaultNotFoundError(`Could not load vault keystore: HTTP ${kr.status}`)

    // Keystore exists — try delegation first (silent), then passphrase
    if (opts.delegation) {
      const appKey = await tryOpenWithGrant(f, podUrl, opts.appNamespace)
      if (appKey) {
        return new PodStorage({ podUrl, ...shared, isEncrypted: true, isDelegated: true, appKey })
      }
    }

    if (!opts.onNeedPassphrase) throw new VaultAccessDeniedError(
      'No passphrase callback and no delegation grant found'
    )

    const keystore = (await kr.json()) as Keystore
    const passphrase = await opts.onNeedPassphrase()
    const vaultKey = await openKeystore(passphrase, keystore)
    const appKey = await deriveAppKey(vaultKey, opts.appNamespace)

    return new PodStorage({ podUrl, ...shared, isEncrypted: true, appKey })
  }

  /**
   * Clear the vault key from memory.
   * Any subsequent put/get/delete/list calls will throw VaultLockedError.
   * Call PodStorage.open() again to unlock.
   */
  lock(): void {
    this._appKey = null
  }

  // ── Public file API ──────────────────────────────────────────────────────

  /** Write a file. Replaces any existing file with the same name. */
  async put(name: string, data: Uint8Array, contentType = 'application/octet-stream'): Promise<void> {
    if (!this.isEncrypted) {
      await this._ensureContainer(this._appBaseUrl)
      const r = await this._fetch(this._plaintextUrl(name), {
        method: 'PUT',
        headers: { 'Content-Type': contentType },
        body: data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
      })
      if (!r.ok) throw new Error(`Could not write file: HTTP ${r.status}`)
      return
    }

    const key = this._requireKey()
    const manifest = await this._readManifest()
    const existing = findEntry(manifest, name)
    const id = existing?.id ?? globalThis.crypto.randomUUID()

    await this._ensureContainer(this._appBaseUrl)

    const encrypted = await encryptBytes(key, data)
    const r = await this._fetch(`${this._appBaseUrl}${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: encrypted.buffer.slice(encrypted.byteOffset, encrypted.byteOffset + encrypted.byteLength) as ArrayBuffer,
    })
    if (!r.ok) throw new Error(`Could not write encrypted file: HTTP ${r.status}`)

    const entry: ManifestEntry = {
      id,
      name,
      contentType,
      createdAt: existing?.createdAt ?? new Date().toISOString(),
      size: data.byteLength,
    }
    const newManifest = addEntry(manifest, entry)
    await this._writeManifest(newManifest)
    if (this._rdfIndex) {
      await writeSidecar(this._fetch, this._podUrl, this._appNamespace, newManifest.entries)
    }
  }

  /** Read and decrypt a file by logical name. Throws if not found. */
  async get(name: string): Promise<Uint8Array> {
    if (!this.isEncrypted) {
      const r = await this._fetch(this._plaintextUrl(name))
      if (r.status === 404) throw new Error(`File not found: ${name}`)
      if (!r.ok) throw new Error(`Could not read file: HTTP ${r.status}`)
      return new Uint8Array(await r.arrayBuffer())
    }

    const key = this._requireKey()
    const manifest = await this._readManifest()
    const entry = findEntry(manifest, name)
    if (!entry) throw new Error(`File not found: ${name}`)

    const r = await this._fetch(`${this._appBaseUrl}${entry.id}`)
    if (r.status === 404) throw new VaultCorruptError(`Encrypted file missing for: ${name}`)
    if (!r.ok) throw new Error(`Could not read encrypted file: HTTP ${r.status}`)

    return decryptBytes(key, new Uint8Array(await r.arrayBuffer()))
  }

  /** Delete a file by logical name. No-op if not found. */
  async delete(name: string): Promise<void> {
    if (!this.isEncrypted) {
      await this._fetch(this._plaintextUrl(name), { method: 'DELETE' })
      return
    }

    const key = this._requireKey()
    const manifest = await this._readManifest()
    const entry = findEntry(manifest, name)
    if (!entry) return

    await this._fetch(`${this._appBaseUrl}${entry.id}`, { method: 'DELETE' })
    const newManifest = removeEntry(manifest, name)
    await this._writeManifest(newManifest)
    if (this._rdfIndex) {
      await writeSidecar(this._fetch, this._podUrl, this._appNamespace, newManifest.entries)
    }
  }

  /**
   * List files. In encrypted mode returns full ManifestEntry objects.
   * In plaintext mode returns an empty array (LDP container parsing not implemented).
   */
  async list(): Promise<ManifestEntry[]> {
    if (!this.isEncrypted) return []
    const manifest = await this._readManifest()
    return manifest.entries
  }

  // ── Sidecar and delegation methods ───────────────────────────────────────

  /**
   * Regenerate the RDF sidecar index from the current manifest.
   * The sidecar is a derived cache — call this to repair a stale or missing
   * sidecar, or to write an initial sidecar for an existing vault.
   * No-op in plaintext mode.
   */
  async rebuildRdfIndex(): Promise<void> {
    if (!this.isEncrypted) return
    const manifest = await this._readManifest()
    await writeSidecar(this._fetch, this._podUrl, this._appNamespace, manifest.entries)
  }

  /**
   * Generate (or retrieve) this app's ECDH delegation keypair and publish
   * the public key to the pod at /vault/.delegation-keys/{namespace}.json.
   * Call this in App B before asking App A to run grantAccess().
   * Returns the URL where the public key was written.
   */
  async registerDelegationKey(deviceName?: string): Promise<string> {
    const { publicKeyJwk, thumbprint } = await getOrCreateDelegationKeyPair(this._appNamespace)
    return publishDelegationPublicKey(
      this._fetch, this._podUrl, this._appNamespace, publicKeyJwk, thumbprint, deviceName,
    )
  }

  /**
   * Create a delegation grant so another app can decrypt this namespace
   * without the user re-entering their passphrase.
   *
   * The recipient app must have called registerDelegationKey() first.
   * The grantor (this storage instance) must be open in encrypted mode.
   *
   * @param opts.granterWebId - WebID of the user creating the grant
   * @param opts.recipientKeyUrl - URL of the recipient's delegation public key
   *   document (as returned by their registerDelegationKey()). Defaults to
   *   the standard path for this namespace on the same pod.
   * @param opts.expiresAt - Optional expiry date for the grant
   */
  async grantAccess(opts: {
    granterWebId: string
    recipientKeyUrl?: string
    expiresAt?: Date
  }): Promise<void> {
    if (!this.isEncrypted) throw new Error('Cannot grant access: storage is in plaintext mode')
    const appKey = this._requireKey()

    const keyUrl = opts.recipientKeyUrl
    if (!keyUrl) throw new Error('recipientKeyUrl is required — delegation keys are now per-device at /vault/.delegation-keys/{namespace}/{thumbprint}.json')
    const r = await this._fetch(keyUrl)
    if (!r.ok) throw new Error(`Could not fetch recipient delegation key: HTTP ${r.status}`)
    const { publicKeyJwk, thumbprint } = (await r.json()) as DelegationPublicKeyDocument

    await createAndWriteGrant(
      this._fetch, this._podUrl, this._appNamespace,
      appKey, opts.granterWebId, publicKeyJwk, thumbprint,
      opts.expiresAt ?? null,
    )
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private get _appBaseUrl(): string {
    return this.isEncrypted
      ? `${this._podUrl}vault/${this._appNamespace}/`
      : `${this._podUrl}${this._appNamespace}/`
  }

  private get _manifestUrl(): string {
    return `${this._appBaseUrl}.manifest`
  }

  private _plaintextUrl(name: string): string {
    return `${this._appBaseUrl}${encodeURIComponent(name)}`
  }

  private _requireKey(): CryptoKey {
    if (!this._appKey) throw new VaultLockedError()
    return this._appKey
  }

  private async _readManifest(): Promise<Manifest> {
    const key = this._requireKey()
    const r = await this._fetch(this._manifestUrl)
    if (r.status === 404) return emptyManifest()
    if (!r.ok) throw new VaultCorruptError(`Could not read manifest: HTTP ${r.status}`)
    return decryptManifest(key, new Uint8Array(await r.arrayBuffer()))
  }

  private async _writeManifest(manifest: Manifest): Promise<void> {
    const key = this._requireKey()
    const encrypted = await encryptManifest(key, manifest)
    const r = await this._fetch(this._manifestUrl, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: encrypted.buffer.slice(encrypted.byteOffset, encrypted.byteOffset + encrypted.byteLength) as ArrayBuffer,
    })
    if (!r.ok) throw new VaultCorruptError(`Could not write manifest: HTTP ${r.status}`)
  }

  private async _ensureContainer(url: string): Promise<void> {
    const r = await this._fetch(url, { method: 'HEAD' })
    if (r.ok) return
    const ttl = '@prefix ldp: <http://www.w3.org/ns/ldp#>.\n<> a ldp:BasicContainer .\n'
    const cr = await this._fetch(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/turtle' },
      body: ttl,
    })
    if (!cr.ok && cr.status !== 409) {
      throw new Error(`Could not create container at ${url}: HTTP ${cr.status}`)
    }
  }
}
