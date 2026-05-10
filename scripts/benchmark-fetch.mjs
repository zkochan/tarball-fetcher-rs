import assert from 'node:assert/strict'
import { mkdir, readdir, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const { fetchTarball } = require('../index.js')

const defaultPackageName = 'typescript'
const defaultVersion = '6.0.3'
const defaultStoreDir = 'pnpm-store'

function parseArgs(argv) {
  const options = {
    packageName: defaultPackageName,
    version: defaultVersion,
    runs: 10,
    warmups: 1,
    storeDir: defaultStoreDir,
    clean: true,
    json: false,
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    const readValue = () => {
      const value = argv[++i]
      if (value == null || value.startsWith('--')) {
        throw new Error(`Missing value for ${arg}`)
      }
      return value
    }

    switch (arg) {
      case '--url':
        options.url = readValue()
        break
      case '--integrity':
        options.integrity = readValue()
        break
      case '--package':
        options.packageName = readValue()
        break
      case '--version':
        options.version = readValue()
        break
      case '--runs':
        options.runs = Number.parseInt(readValue(), 10)
        break
      case '--warmups':
        options.warmups = Number.parseInt(readValue(), 10)
        break
      case '--store-dir':
        options.storeDir = readValue()
        break
      case '--no-clean':
        options.clean = false
        break
      case '--json':
        options.json = true
        break
      case '--help':
      case '-h':
        options.help = true
        break
      default:
        throw new Error(`Unknown argument: ${arg}`)
    }
  }

  if (!Number.isInteger(options.runs) || options.runs < 1) {
    throw new Error('--runs must be a positive integer')
  }
  if (!Number.isInteger(options.warmups) || options.warmups < 0) {
    throw new Error('--warmups must be a non-negative integer')
  }

  return options
}

function printHelp() {
  console.log(`Usage: node scripts/benchmark-fetch.mjs [options]

Options:
  --url <url>              Tarball URL. Defaults to npm metadata tarball.
  --integrity <integrity>  Tarball integrity. Required with --url.
  --package <name>        npm package name for metadata lookup. Default: ${defaultPackageName}
  --version <version>     npm package version for metadata lookup. Default: ${defaultVersion}
  --runs <count>          Measured runs. Default: 10
  --warmups <count>       Warmup runs before measuring. Default: 1
  --store-dir <path>      Store directory to clear between runs. Default: ${defaultStoreDir}
  --no-clean              Reuse the store between runs.
  --json                  Print machine-readable JSON.
  --help                  Show this help.

Examples:
  node scripts/benchmark-fetch.mjs --runs 20
  node scripts/benchmark-fetch.mjs --url http://127.0.0.1:8123/typescript.tgz --integrity sha512-...
`)
}

async function emptyStoreDir(dir) {
  await mkdir(dir, { recursive: true })
  const entries = await readdir(dir)
  await Promise.all(entries.map((entry) => rm(join(dir, entry), { recursive: true, force: true })))
}

async function resolveTarball(options) {
  if (options.url != null) {
    assert.ok(options.integrity, '--integrity is required when --url is provided')
    return {
      name: options.url,
      url: options.url,
      integrity: options.integrity,
    }
  }

  const metadataUrl = `https://registry.npmjs.org/${options.packageName}/${options.version}`
  const response = await fetch(metadataUrl)
  if (!response.ok) {
    throw new Error(`Failed to fetch ${metadataUrl}: ${response.status} ${response.statusText}`)
  }

  const metadata = await response.json()
  const { tarball, integrity } = metadata.dist ?? {}

  assert.ok(tarball, 'registry metadata includes a tarball URL')
  assert.ok(integrity, 'registry metadata includes an integrity checksum')

  return {
    name: `${options.packageName}@${metadata.version}`,
    url: tarball,
    integrity,
  }
}

async function runOnce(target, options) {
  if (options.clean) {
    await emptyStoreDir(options.storeDir)
  }

  const start = performance.now()
  const files = await fetchTarball(target.url, target.integrity)
  const durationMs = performance.now() - start

  return {
    durationMs,
    fileCount: Object.keys(files).length,
  }
}

function percentile(sortedValues, percentileValue) {
  const index = (sortedValues.length - 1) * percentileValue
  const lower = Math.floor(index)
  const upper = Math.ceil(index)

  if (lower === upper) {
    return sortedValues[lower]
  }

  const weight = index - lower
  return sortedValues[lower] * (1 - weight) + sortedValues[upper] * weight
}

function summarize(results) {
  const durations = results.map((result) => result.durationMs).sort((a, b) => a - b)
  const total = durations.reduce((sum, duration) => sum + duration, 0)

  return {
    minMs: durations[0],
    medianMs: percentile(durations, 0.5),
    p90Ms: percentile(durations, 0.9),
    maxMs: durations[durations.length - 1],
    meanMs: total / durations.length,
  }
}

function formatMs(value) {
  return `${value.toFixed(2)}ms`
}

async function main() {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    printHelp()
    return
  }

  const target = await resolveTarball(options)
  const warmups = []
  const runs = []

  if (!options.json) {
    console.log(`Benchmarking ${target.name}`)
    console.log(target.url)
    console.log(`runs=${options.runs} warmups=${options.warmups} clean=${options.clean}`)
  }

  for (let i = 0; i < options.warmups; i++) {
    const result = await runOnce(target, options)
    warmups.push(result)
    if (!options.json) {
      console.log(`warmup ${i + 1}: ${formatMs(result.durationMs)} (${result.fileCount} files)`)
    }
  }

  for (let i = 0; i < options.runs; i++) {
    const result = await runOnce(target, options)
    runs.push(result)
    if (!options.json) {
      console.log(`run ${i + 1}: ${formatMs(result.durationMs)} (${result.fileCount} files)`)
    }
  }

  if (options.clean) {
    await emptyStoreDir(options.storeDir)
  }

  const summary = summarize(runs)
  const output = {
    target,
    options: {
      runs: options.runs,
      warmups: options.warmups,
      clean: options.clean,
      storeDir: options.storeDir,
    },
    warmups,
    runs,
    summary,
  }

  if (options.json) {
    console.log(JSON.stringify(output, null, 2))
    return
  }

  console.log('summary:')
  console.log(`  min:    ${formatMs(summary.minMs)}`)
  console.log(`  median: ${formatMs(summary.medianMs)}`)
  console.log(`  p90:    ${formatMs(summary.p90Ms)}`)
  console.log(`  max:    ${formatMs(summary.maxMs)}`)
  console.log(`  mean:   ${formatMs(summary.meanMs)}`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    await main()
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  }
}
