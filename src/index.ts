// Public API
export { PodStorage } from './pod-storage.js'
export type { PodStorageOptions } from './pod-storage.js'

// Types
export type { ManifestEntry, Manifest } from './manifest.js'
export type { Keystore } from './keys.js'

// Errors
export {
  VaultNotFoundError,
  WrongPassphraseError,
  VaultLockedError,
  VaultCorruptError,
  VaultAccessDeniedError,
} from './errors.js'

// Sidecar (RDF discoverability)
export { generateSidecarTurtle, writeSidecar, sidecarUrl } from './sidecar.js'

// Delegation (cross-app key grants)
export {
  getOrCreateDelegationKeyPair,
  publishDelegationPublicKey,
  createAndWriteGrant,
  tryOpenWithGrant,
  unwrapGrantKey,
  computeThumbprint,
  delegationKeyUrl,
  grantUrl,
} from './delegation.js'
export type { GrantDocument, DelegationPublicKeyDocument } from './delegation.js'

// Lower-level exports for advanced use (e.g. building custom storage)
export { openKeystore } from './keys.js'
export { generateVaultKey, deriveAppKey, encryptBytes, decryptBytes } from './crypto.js'
export { encryptManifest, decryptManifest, addEntry, removeEntry, findEntry, emptyManifest } from './manifest.js'
