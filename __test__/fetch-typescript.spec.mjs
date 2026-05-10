import { mkdir, mkdtemp, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import test from 'ava'

import { emptyPnpmStoreDir } from '../scripts/fetch-typescript.mjs'

test('emptyPnpmStoreDir removes existing store contents', async (t) => {
  const storeDir = await mkdtemp(join(tmpdir(), 'pnpm-store-'))
  await mkdir(join(storeDir, 'ab'))
  await writeFile(join(storeDir, 'ab', 'entry'), 'cached content')

  await emptyPnpmStoreDir(storeDir)

  t.deepEqual(await readdir(storeDir), [])
})
