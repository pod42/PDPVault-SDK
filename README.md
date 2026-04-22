# @privatedatapod/vault-sdk

Client-side encrypted file storage for [Solid](https://solidproject.org/) pods. Zero dependencies. Pure [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

**Your server never sees plaintext.** Files are AES-256-GCM encrypted in the browser before being written to the pod, and decrypted after reading — the encryption key never leaves the client.

---

## Features

- **AES-256-GCM encryption** — files are encrypted before they leave the browser
- **PBKDF2 key derivation** — 600,000 iterations; brute-force resistant
- **Per-app key isolation** — each `appNamespace` gets its own derived key via HKDF; apps cannot read each other's data even if they share a pod
- **Passphrase-free delegation** — after a one-time approval on the user's Account page, your app opens the vault silently on every subsequent visit
- **Graceful plaintext fallback** — the same API works for Free-plan users and pods on other Solid servers; `isEncrypted` tells you which mode you're in
- **Zero dependencies** — no third-party crypto libraries; built on native browser APIs

---

## Requirements

- A [Private Data Pod](https://privatedatapod.com) (Pro plan for encrypted mode; Free plan works in plaintext mode)
- An authenticated `fetch` from a Solid OIDC session (e.g. [@inrupt/solid-client-authn-browser](https://github.com/inrupt/solid-client-authn-js))

---

## Installation

```bash
npm install @privatedatapod/vault-sdk
```

---

## Quick start

```ts
import { PodStorage } from '@privatedatapod/vault-sdk'

const storage = await PodStorage.open({
  podUrl: 'https://alice.privatedatapod.com/',
  fetch,                                        // authenticated fetch from Solid OIDC
  appNamespace: 'com.example.myapp',            // stable reverse-DNS id — never change this
  onNeedPassphrase: () => Promise.resolve(prompt('Vault passphrase:')),
})

// Write
const bytes = new TextEncoder().encode(JSON.stringify({ hello: 'world' }))
await storage.put('data.json', bytes, 'application/json')

// Read
const raw = await storage.get('data.json')
if (raw) {
  const obj = JSON.parse(new TextDecoder().decode(raw))
}

// List
const files = await storage.list()
// [{ id, name, contentType, createdAt, size? }, ...]

// Delete
await storage.delete('data.json')

// Lock when done (clears key from memory)
storage.lock()
```

---

## API reference

### `PodStorage.open(options)` → `Promise<PodStorage>`

Opens storage for a pod. Resolves with a `PodStorage` instance.

| Option | Type | Required | Description |
|---|---|---|---|
| `podUrl` | `string` | ✓ | User's pod root URL, e.g. `https://alice.privatedatapod.com/` |
| `appNamespace` | `string` | ✓ | Stable reverse-DNS identifier for your app. **Never change this after launch** — changing it derives a different key and makes existing files unreadable. |
| `fetch` | `typeof globalThis.fetch` | | Authenticated fetch from Solid OIDC. Falls back to `globalThis.fetch` if omitted. |
| `onNeedPassphrase` | `() => Promise<string>` | | Called when the vault is found and a passphrase is needed. Required unless using delegation-only mode. |
| `delegation` | `boolean` | | When `true`, try a delegation grant first (silent open). Falls back to `onNeedPassphrase` if no grant is found. Default: `false`. |
| `rdfIndex` | `boolean` | | When `true`, maintain an RDF sidecar index for Solid-standard discoverability. Filenames are stored in plaintext in the sidecar. Default: `false`. |

**Behaviour:**

- If `/vault/.keystore` exists on the pod → **encrypted mode**
- If no keystore (404) → **plaintext mode** (`isEncrypted === false`)
- 401/403 → throws `VaultAccessDeniedError`

---

### `storage.put(name, bytes, contentType)` → `Promise<void>`

Write a file. In encrypted mode the bytes are encrypted before upload; in plaintext mode they are written as-is.

```ts
const buf = await file.arrayBuffer()
await storage.put(file.name, new Uint8Array(buf), file.type)
```

---

### `storage.get(name)` → `Promise<Uint8Array | null>`

Read a file by name. Returns `null` if the file doesn't exist.

```ts
const bytes = await storage.get('notes.txt')
if (bytes) {
  console.log(new TextDecoder().decode(bytes))
}
```

---

### `storage.list()` → `Promise<ManifestEntry[]>`

List all files in this app's storage.

```ts
const files = await storage.list()
// ManifestEntry: { id: string, name: string, contentType: string, createdAt: string, size?: number }
```

---

### `storage.delete(name)` → `Promise<void>`

Delete a file by name.

---

### `storage.lock()` → `void`

Clear the vault key from memory. Call this on logout and on `beforeunload`.

```ts
window.addEventListener('beforeunload', () => storage.lock())
```

---

### `storage.isEncrypted` → `boolean`

`true` when operating in encrypted vault mode, `false` in plaintext mode.

---

### `storage.isDelegated` → `boolean`

`true` when this session was opened via a delegation grant (no passphrase was entered).

---

## Error handling

```ts
import {
  WrongPassphraseError,      // wrong passphrase — prompt again
  VaultNotFoundError,        // no keystore (plaintext mode, not an error in most cases)
  VaultLockedError,          // operation attempted after lock()
  VaultCorruptError,         // keystore can't be parsed or decrypted
  VaultAccessDeniedError,    // 401/403 from pod (session expired or grant revoked)
} from '@privatedatapod/vault-sdk'

try {
  const storage = await PodStorage.open({ ... })
} catch (err) {
  if (err instanceof WrongPassphraseError)   { /* prompt for passphrase again */ }
  if (err instanceof VaultAccessDeniedError) { /* re-authenticate */ }
  if (err instanceof VaultCorruptError)      { /* keystore is damaged */ }
}
```

---

## Checking vault status before opening

Before calling `PodStorage.open()`, you can check whether the user's vault is set up:

```ts
const res = await fetch('https://privatedatapod.com/api/vault/status', {
  credentials: 'include',
})
const { enabled, provisioned } = await res.json()
// enabled:     user is on the Pro plan
// provisioned: /vault/ container has been initialised on the pod

if (!enabled) {
  // Show upgrade prompt → https://privatedatapod.com/#pricing
} else if (!provisioned) {
  // Direct user to their Account page to set up the vault
} else {
  const storage = await PodStorage.open({ ... })
}
```

---

## Delegation — passphrase-free vault access

> Available from v0.2.0

Delegation lets your app open the vault silently on every subsequent visit, without asking the user for their passphrase. The user approves your app once on their Account page at privatedatapod.com. After approval, your app derives the vault key from a cryptographic grant stored on the pod. **The passphrase never enters your app at all.**

### How it works

1. Your app generates an ECDH P-256 keypair on first run. The private key is stored in IndexedDB (non-extractable). The public key is published to the pod.
2. The user sees your app listed as "pending approval" on their Account page. They enter their passphrase once. The account page derives your app's namespace key and wraps it for your public key using ECDH + AES-KW, writing a grant to the pod.
3. On every subsequent open, your app reads the grant, performs ECDH with its stored private key, and unwraps the app key — no passphrase required.

### Usage

```ts
// First run: register the delegation key and open with passphrase as fallback
const storage = await PodStorage.open({
  podUrl, fetch,
  appNamespace: 'com.example.myapp',
  delegation: true,
  onNeedPassphrase: () => Promise.resolve(prompt('Vault passphrase:')),
})

await storage.registerDelegationKey()
// Writes public key to /vault/.delegation-keys/{appNamespace}.json
// Safe to call every session — it is a no-op if the key is already registered

if (!storage.isDelegated) {
  // Grant not yet approved — prompt the user to visit their Account page
  showMessage('Please approve vault access on your Account page at privatedatapod.com.')
}
```

```ts
// Subsequent visits: open silently, no passphrase
const storage = await PodStorage.open({
  podUrl, fetch,
  appNamespace: 'com.example.myapp',
  delegation: true,
  // no onNeedPassphrase — throws VaultAccessDeniedError if grant not found
}).catch(err => {
  if (err instanceof VaultAccessDeniedError) return null
  throw err
})

if (!storage) {
  showApprovalPrompt('https://privatedatapod.com/.account/login/')
  return
}

// storage.isDelegated === true
await storage.registerDelegationKey() // no-op — already registered
```

---

## React integration

### Basic hook (passphrase mode)

```tsx
import { useRef, useState } from 'react'
import { PodStorage, WrongPassphraseError } from '@privatedatapod/vault-sdk'

export function useVaultStorage(podUrl: string, fetch: typeof globalThis.fetch, appNamespace: string) {
  const storageRef = useRef<PodStorage | null>(null)
  const [isEncrypted, setIsEncrypted] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  async function open(onNeedPassphrase: () => Promise<string>) {
    try {
      const s = await PodStorage.open({ podUrl, fetch, appNamespace, onNeedPassphrase })
      storageRef.current = s
      setIsEncrypted(s.isEncrypted)
    } catch (err) {
      setError(err as Error)
      throw err
    }
  }

  function lock() {
    storageRef.current?.lock()
    storageRef.current = null
  }

  return { storage: storageRef.current, isEncrypted, error, open, lock }
}
```

### Hook with delegation

```tsx
import { useRef, useState } from 'react'
import { PodStorage, VaultAccessDeniedError } from '@privatedatapod/vault-sdk'

export function useVaultStorage(podUrl: string, fetch: typeof globalThis.fetch, appNamespace: string) {
  const storageRef = useRef<PodStorage | null>(null)
  const [isDelegated, setIsDelegated] = useState(false)
  const [needsApproval, setNeedsApproval] = useState(false)
  const [isEncrypted, setIsEncrypted] = useState(false)

  async function open() {
    try {
      const s = await PodStorage.open({ podUrl, fetch, appNamespace, delegation: true })
      await s.registerDelegationKey()  // no-op if already registered
      storageRef.current = s
      setIsEncrypted(s.isEncrypted)
      setIsDelegated(s.isDelegated)
      setNeedsApproval(!s.isDelegated)
    } catch (err) {
      if (err instanceof VaultAccessDeniedError) {
        setNeedsApproval(true)
      } else throw err
    }
  }

  function lock() {
    storageRef.current?.lock()
    storageRef.current = null
    setIsDelegated(false)
  }

  return { storage: storageRef.current, isEncrypted, isDelegated, needsApproval, open, lock }
}
```

---

## How encryption works

| Layer | Algorithm | Detail |
|---|---|---|
| Key derivation | PBKDF2-SHA-256 | 600,000 iterations; salt stored in keystore |
| Per-app key isolation | HKDF-SHA-256 | `appNamespace` is the info parameter |
| File encryption | AES-256-GCM | Random 12-byte IV per file; authenticated |
| Manifest encryption | AES-256-GCM | Encrypted JSON mapping logical names → opaque IDs |
| Delegation key wrapping | ECDH P-256 + AES-KW | Grant document written by the Account page |

The keystore lives at `/vault/.keystore` on the pod. It contains the vault key wrapped by the user's passphrase. The keystore is readable by the server; the plaintext vault key is never transmitted.

---

## Important rules

1. **`appNamespace` is permanent.** It drives the HKDF key derivation. If you change it after launch, all existing files become unreadable. Use a stable reverse-DNS string like `com.yourcompany.yourapp`.

2. **Cache the `storage` instance for the session.** Do not call `PodStorage.open()` on every operation — it fetches the keystore and prompts for a passphrase each time.

3. **Never provision the vault yourself.** Vault setup (passphrase creation, keystore generation) happens on the user's Account page at privatedatapod.com. Your app only unlocks an existing vault.

4. **Call `storage.lock()` on logout and `beforeunload`.** This clears the derived key from memory.

5. **`isEncrypted === false` is not an error.** It means the user is on the Free plan, has not set up their vault yet, or is using a Solid server other than privatedatapod.com. Your read/write code works identically in both modes.

6. **To show an upgrade prompt:** check that `podUrl` ends with `.privatedatapod.com` before surfacing the upgrade CTA, so you don't confuse users on other Solid providers.

7. **Passphrase recovery is handled by the Account page.** If the user forgets their passphrase they can reset it using their recovery code. You do not need to handle this.

8. **Delegation: call `registerDelegationKey()` every session.** It is idempotent — a no-op if the key is already registered. Never pass `onNeedPassphrase` in delegation-only mode if you don't want to fall back to prompting.

---

## Links

- [Private Data Pod](https://privatedatapod.com) — hosted Solid pods with vault support
- [Developer Center](https://developers.privatedatapod.com) — deploy Solid apps, API docs
- [Solid Project](https://solidproject.org) — the open specification

---

## License

MIT
