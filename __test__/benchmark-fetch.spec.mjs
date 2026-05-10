import { createServer } from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import test from 'ava'

import { parseArgs, prepareLocalTarget, resolvePackageSpecs } from '../scripts/benchmark-fetch.mjs'

test('parseArgs enables local benchmark mode', (t) => {
  const options = parseArgs(['--local', '--tarball-cache-dir', '/tmp/cache', '--runs', '3'])

  t.true(options.local)
  t.is(options.tarballCacheDir, '/tmp/cache')
  t.is(options.runs, 3)
})

test('parseArgs accepts multiple package specs', (t) => {
  const options = parseArgs(['--packages', 'typescript@6.0.3,react@19.2.1,lodash'])

  t.deepEqual(options.packageSpecs, ['typescript@6.0.3', 'react@19.2.1', 'lodash'])
})

test('resolvePackageSpecs parses scoped packages and default versions', (t) => {
  const specs = resolvePackageSpecs({
    packageName: 'typescript',
    version: '6.0.3',
    packageSpecs: ['@scope/pkg@1.2.3', 'react@19.2.1', 'lodash'],
  })

  t.deepEqual(specs, [
    { packageName: '@scope/pkg', version: '1.2.3' },
    { packageName: 'react', version: '19.2.1' },
    { packageName: 'lodash', version: 'latest' },
  ])
})

test('prepareLocalTarget downloads once and returns a localhost URL', async (t) => {
  const cacheDir = await mkdtemp(join(tmpdir(), 'tarball-fetcher-bench-'))
  const tarball = Buffer.from('fake tarball')
  let requests = 0

  const remoteServer = createServer((request, response) => {
    requests++
    t.is(request.url, '/package.tgz')
    response.end(tarball)
  })

  await new Promise((resolve) => remoteServer.listen(0, '127.0.0.1', resolve))

  try {
    const { port } = remoteServer.address()
    const target = {
      name: 'package@1.0.0',
      url: `http://127.0.0.1:${port}/package.tgz`,
      integrity: 'sha512-test',
    }

    const local = await prepareLocalTarget(target, { tarballCacheDir: cacheDir })

    t.regex(local.url, /^http:\/\/127\.0\.0\.1:\d+\/package\.tgz$/)
    t.is(local.integrity, target.integrity)
    t.is(local.name, `${target.name} (local)`)
    t.is(requests, 1)

    const response = await fetch(local.url)
    t.deepEqual(Buffer.from(await response.arrayBuffer()), tarball)

    await local.close()
  } finally {
    await new Promise((resolve) => remoteServer.close(resolve))
    await rm(cacheDir, { recursive: true, force: true })
  }
})
