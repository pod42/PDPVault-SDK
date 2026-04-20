# Vault SDK — AI Agent Prompt

Copy the block below into GitHub Copilot Chat, Cursor, Claude, or any other AI coding assistant before asking it to build a feature that uses the Vault SDK.

---

```
You are helping build a web app that integrates the PrivateDataPod Vault SDK
(@privatedatapod/vault-sdk) for client-side encrypted file storage in Solid pods.

## What the SDK does

All encryption runs in the browser using the Web Crypto API. The server never
sees plaintext. Files are AES-256-GCM encrypted. The encryption key is derived
from the user's passphrase via PBKDF2 (600,000 iterations) and stored wrapped
in the user's Solid pod at /vault/.keystore.

Per-app keys are derived via HKDF so each app gets an isolated encryption key,
but the user only needs one passphrase.

Users without a vault keystore get the same API in plaintext mode
(isEncrypted === false). This includes Free plan users, users who have not
finished vault setup, and users on other Solid servers. Your code is identical
either way; the SDK switches automatically.

## Installation

npm install @privatedatapod/vault-sdk

## Core API

### Open storage (do this once per session)

import { PodStorage } from '@privatedatapod/vault-sdk'

const storage = await PodStorage.open({
  podUrl: 'https://alice.privatedatapod.com/', // user's pod root URL
  fetch,                                        // authenticated fetch from Solid OIDC
  appNamespace: 'com.example.myapp',           // stable reverse-DNS id — never change this
  onNeedPassphrase: () => Promise<string>,      // called to collect passphrase from user
})

### Write a file

const bytes = new TextEncoder().encode(JSON.stringify({ key: 'value' }))
await storage.put('data.json', bytes, 'application/json')

### Read a file

const bytes = await storage.get('data.json')  // returns Uint8Array | null
if (bytes) {
  const obj = JSON.parse(new TextDecoder().decode(bytes))
}

### Store binary (e.g. from a file input)

const buf = await file.arrayBuffer()
await storage.put(file.name, new Uint8Array(buf), file.type)

### List files

const files = await storage.list()
// ManifestEntry[]: [{ id, name, contentType, createdAt, size? }]

### Delete a file

await storage.delete('data.json')

### Lock the vault (call on logout or page unload)

storage.lock()

### Check encryption mode

storage.isEncrypted  // true = encrypted, false = plaintext (Free plan)

## Check vault status before opening

const res = await fetch('https://privatedatapod.com/api/vault/status', {
  credentials: 'include',
})
const { enabled, provisioned } = await res.json()
// enabled:     user is on the Pro plan
// provisioned: /vault/ container exists in the pod

if (!enabled) {
  // Show upgrade prompt
} else if (!provisioned) {
  // Direct user to their Account page to set up the vault
} else {
  // Safe to call PodStorage.open()
}

## Error handling

import {
  WrongPassphraseError,    // wrong passphrase — prompt again
  VaultNotFoundError,      // no keystore found (plaintext mode)
  VaultLockedError,        // operation attempted before unlock
  VaultCorruptError,       // keystore can't be parsed or decrypted
  VaultAccessDeniedError,  // 401/403 from pod (session expired)
} from '@privatedatapod/vault-sdk'

try {
  const storage = await PodStorage.open({ ... })
} catch (err) {
  if (err instanceof WrongPassphraseError) { /* prompt again */ }
  if (err instanceof VaultAccessDeniedError) { /* re-authenticate */ }
}

## Rules — follow these exactly

1. NEVER ask the user to create a passphrase in your app. Vault setup happens
   on the user's Account page at privatedatapod.com. Your app only unlocks an
   existing vault via onNeedPassphrase.

2. appNamespace must never change after launch. Changing it derives a different
   key and makes all existing files unreadable. Use a reverse-DNS string:
   com.yourcompany.yourapp

3. Cache the storage instance for the session. Do not call PodStorage.open()
   on every operation — it prompts for the passphrase each time.

4. Call storage.lock() on logout and on the window 'beforeunload' event.

5. If storage.isEncrypted is false, no vault keystore was found. This can
   mean the user is on the Free plan, has not set up their vault yet, or is
   using a non-privatedatapod.com Solid server (vault setup requires a Pro
   account on privatedatapod.com). Either work in plaintext mode or show an
   upgrade/info prompt. Do not treat this as an error.
   To detect non-privatedatapod users: check that the podUrl hostname ends
   with '.privatedatapod.com' before showing an upgrade prompt.

6. If provisioned is false, link the user to privatedatapod.com and their
   Account page. Do not try to create or provision the vault yourself.

7. If the user forgets their passphrase, they can reset it on the Account page
   using their recovery code. You do not need to handle passphrase recovery.

## React integration pattern

import { useState, useRef } from 'react'
import { PodStorage, WrongPassphraseError } from '@privatedatapod/vault-sdk'

export function useVaultStorage(podUrl, fetch, appNamespace) {
  const storageRef = useRef(null)
  const [isEncrypted, setIsEncrypted] = useState(false)
  const [error, setError] = useState(null)

  async function open(onNeedPassphrase) {
    try {
      const s = await PodStorage.open({
        podUrl, fetch, appNamespace, onNeedPassphrase,
      })
      storageRef.current = s
      setIsEncrypted(s.isEncrypted)
    } catch (err) {
      setError(err)
      throw err
    }
  }

  function lock() {
    storageRef.current?.lock()
    storageRef.current = null
  }

  return { storage: storageRef.current, isEncrypted, error, open, lock }
}

## Delegation — passphrase-free vault access (0.2.0+)

Delegation lets your app open the vault silently on subsequent visits without
asking the user for their passphrase. The user approves your app once on their
Account page at privatedatapod.com. After approval, your app opens the vault
using a cryptographic grant stored on the pod. The passphrase never enters
your app at all.

### How it works

1. Your app generates an ECDH P-256 keypair the first time it runs.
   The private key is stored in IndexedDB (non-extractable, never leaves the
   browser). The public key is published to the user's pod.

2. The user sees your app listed as "pending approval" on their Account page
   vault card. They enter their passphrase once. The account page derives your
   app's namespace key and wraps it for your public key using ECDH + AES-KW,
   writing a grant document to the pod.

3. On every subsequent open, your app finds the grant, performs ECDH with its
   stored private key, and unwraps the app key — no passphrase required.

### Usage

#### Step 1: Register the delegation key (call once on first run)

const storage = await PodStorage.open({
  podUrl, fetch, appNamespace,
  delegation: true,
  // onNeedPassphrase omitted — we don't ask for it
})
await storage.registerDelegationKey()
// Writes public key to /vault/.delegation-keys/{appNamespace}.json on the pod

#### Step 2: Tell the user to approve on their Account page

if (!storage.isDelegated) {
  // No grant yet — prompt the user to visit their Account page
  showMessage('Open your Account page at privatedatapod.com to approve access.')
}

#### Step 3: On subsequent visits, open silently

try {
  const storage = await PodStorage.open({
    podUrl, fetch, appNamespace,
    delegation: true,
    // no onNeedPassphrase — throws VaultAccessDeniedError if no grant found
  })
  // storage.isDelegated === true if opened via grant
} catch (err) {
  if (err instanceof VaultAccessDeniedError) {
    // Grant was revoked or never approved — direct user to Account page
    showMessage('Please re-approve vault access on your Account page.')
  }
}

### Full delegation open pattern (with fallback message)

const storage = await PodStorage.open({
  podUrl, fetch,
  appNamespace: 'com.example.myapp',
  delegation: true,
}).catch(err => {
  if (err instanceof VaultAccessDeniedError) return null
  throw err
})

if (!storage) {
  // Not approved yet or grant revoked
  showApprovalPrompt('https://privatedatapod.com/.account/login/')
  return
}

// storage is open and ready — storage.isDelegated is true

### React hook with delegation

import { useRef, useState, useEffect } from 'react'
import { PodStorage, VaultAccessDeniedError } from '@privatedatapod/vault-sdk'

export function useVaultStorage(podUrl, fetch, appNamespace) {
  const storageRef = useRef(null)
  const [isDelegated, setIsDelegated] = useState(false)
  const [needsApproval, setNeedsApproval] = useState(false)
  const [isEncrypted, setIsEncrypted] = useState(false)

  async function open() {
    try {
      const s = await PodStorage.open({
        podUrl, fetch, appNamespace, delegation: true,
      })
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

### Delegation rules

8. Call registerDelegationKey() every time the storage opens — it is a no-op
   if a key is already registered for this namespace. It is safe to call on
   every session.

9. Never pass onNeedPassphrase when using delegation-only mode. If you do not
   want to prompt for a passphrase at all, omit it. VaultAccessDeniedError
   means the user has not approved yet or the grant was revoked.

10. When needsApproval is true, direct the user to their Account page at
    privatedatapod.com — do not build your own approval UI. The account page
    handles passphrase entry, key derivation, and grant writing.

11. storage.isDelegated tells you whether this session was opened via a grant
    (true) or via passphrase (false, only if you also pass onNeedPassphrase).

12. If a grant is revoked (e.g. user loses a device), the next open will throw
    VaultAccessDeniedError. The user re-approves on the Account page — no
    data is lost, no re-encryption needed.
```
