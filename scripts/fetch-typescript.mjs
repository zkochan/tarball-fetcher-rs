import assert from 'node:assert/strict'
import { mkdir, readdir, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const { fetchTarball } = require('../index.js')

const packageName = 'typescript'
const storeDir = 'pnpm-store'

export async function emptyPnpmStoreDir(dir = storeDir) {
  await mkdir(dir, { recursive: true })
  const entries = await readdir(dir)
  await Promise.all(entries.map((entry) => rm(join(dir, entry), { recursive: true, force: true })))
}

async function main() {
  try {
    const version = process.argv[2] ?? 'latest'
    const metadataUrl = `https://registry.npmjs.org/${packageName}/${version}`
    const metadataResponse = await fetch(metadataUrl)

    if (!metadataResponse.ok) {
      throw new Error(`Failed to fetch ${metadataUrl}: ${metadataResponse.status} ${metadataResponse.statusText}`)
    }

    const metadata = await metadataResponse.json()
    const { tarball, integrity } = metadata.dist ?? {}

    assert.ok(tarball, 'registry metadata includes a tarball URL')
    assert.ok(integrity, 'registry metadata includes an integrity checksum')

    console.log(`Fetching ${packageName}@${metadata.version}`)
    console.log(tarball)

    const files = await fetchTarball(tarball, integrity)

    for (const file of ['package.json', 'README.md', 'bin/tsc']) {
      assert.ok(files[file], `tarball contains ${file}`)
    }

    console.log(`Fetched ${Object.keys(files).length} files`)
    console.log(JSON.stringify(files, null, 2))
  } finally {
    await emptyPnpmStoreDir()
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main()
}
