export class VaultNotFoundError extends Error {
  constructor(message = 'Vault not found') {
    super(message)
    this.name = 'VaultNotFoundError'
  }
}

export class WrongPassphraseError extends Error {
  constructor(message = 'Wrong passphrase') {
    super(message)
    this.name = 'WrongPassphraseError'
  }
}

export class VaultLockedError extends Error {
  constructor(message = 'Vault is locked — call PodStorage.open() to unlock') {
    super(message)
    this.name = 'VaultLockedError'
  }
}

export class VaultCorruptError extends Error {
  constructor(message = 'Vault data is corrupt or unreadable') {
    super(message)
    this.name = 'VaultCorruptError'
  }
}

export class VaultAccessDeniedError extends Error {
  constructor(message = 'Access denied to vault resource') {
    super(message)
    this.name = 'VaultAccessDeniedError'
  }
}
