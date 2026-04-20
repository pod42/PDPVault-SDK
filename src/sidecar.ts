/**
 * Owner-only RDF sidecar index for vault namespaces.
 *
 * The sidecar is a Turtle document at /vault/.index.{namespace}.ttl that
 * contains plaintext metadata (filenames, content types, sizes, dates) about
 * the encrypted blobs in a namespace. It lives inside the vault container and
 * therefore inherits the vault's owner-only ACL automatically.
 *
 * The sidecar is a derived cache — the encrypted manifest is the source of
 * truth. It can always be fully regenerated from the manifest + vault key.
 * If the sidecar and manifest disagree, the manifest wins.
 *
 * This enables Solid-standard discoverability for owner agents (backup tools,
 * cross-app search, migration utilities) without exposing file contents.
 */

import type { ManifestEntry } from './manifest.js'

const PDP_NS = 'https://privatedatapod.com/ns/vault#'

/**
 * Generate a Turtle sidecar index document.
 * The container entry records the namespace and manifest URL.
 * Each blob entry records the logical filename, content type, size, and creation date.
 */
export function generateSidecarTurtle(
  podUrl: string,
  appNamespace: string,
  entries: ManifestEntry[],
): string {
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  const containerUrl = `${base}vault/${appNamespace}/`

  const lines = [
    `@prefix ldp:    <http://www.w3.org/ns/ldp#> .`,
    `@prefix schema: <https://schema.org/> .`,
    `@prefix xsd:    <http://www.w3.org/2001/XMLSchema#> .`,
    `@prefix pdp:    <${PDP_NS}> .`,
    ``,
    `<${containerUrl}>`,
    `    a ldp:BasicContainer ;`,
    `    pdp:appNamespace "${appNamespace}" ;`,
    `    pdp:encryptedManifest <${containerUrl}.manifest> .`,
    ``,
  ]

  for (const entry of entries) {
    const blobUrl = `${containerUrl}${entry.id}`
    const safeName = entry.name.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    const safeType = entry.contentType.replace(/"/g, '\\"')
    lines.push(`<${blobUrl}>`)
    lines.push(`    a schema:DigitalDocument ;`)
    lines.push(`    schema:name "${safeName}" ;`)
    lines.push(`    schema:encodingFormat "${safeType}" ;`)
    if (entry.size !== undefined) {
      lines.push(`    schema:contentSize ${entry.size} ;`)
    }
    lines.push(`    schema:dateCreated "${entry.createdAt}"^^xsd:dateTime ;`)
    lines.push(`    pdp:encryptedBlob <${blobUrl}> ;`)
    lines.push(`    pdp:appNamespace "${appNamespace}" .`)
    lines.push(``)
  }

  return lines.join('\n')
}

/**
 * Write the RDF sidecar index to the pod.
 * The sidecar is placed at /vault/.index.{namespace}.ttl, inside the vault
 * container, so it inherits the vault's owner-only ACL with no extra setup.
 */
export async function writeSidecar(
  f: typeof globalThis.fetch,
  podUrl: string,
  appNamespace: string,
  entries: ManifestEntry[],
): Promise<void> {
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  const sidecarUrl = `${base}vault/.index.${appNamespace}.ttl`
  const turtle = generateSidecarTurtle(podUrl, appNamespace, entries)

  const r = await f(sidecarUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'text/turtle' },
    body: turtle,
  })
  if (!r.ok) throw new Error(`Could not write RDF sidecar: HTTP ${r.status}`)
}

/** Return the URL of the sidecar for a given pod + namespace. */
export function sidecarUrl(podUrl: string, appNamespace: string): string {
  const base = podUrl.endsWith('/') ? podUrl : podUrl + '/'
  return `${base}vault/.index.${appNamespace}.ttl`
}
