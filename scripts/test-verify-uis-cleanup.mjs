#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

import { cleanupChromiumProfile } from './verify-uis.mjs';

const calls = [];
const errors = [];
await cleanupChromiumProfile('/tmp/tim-ui-profile', {
  rmProfile: async (...args) => calls.push(args),
  logger: { error: (...args) => errors.push(args.join(' ')) },
});

assert.deepEqual(calls, [[
  '/tmp/tim-ui-profile',
  { recursive: true, force: true, maxRetries: 10, retryDelay: 25 },
]]);
assert.deepEqual(errors, []);

const cleanupError = Object.assign(new Error('directory not empty'), { code: 'ENOTEMPTY' });
await assert.rejects(
  cleanupChromiumProfile('/tmp/tim-ui-profile', {
    rmProfile: async () => { throw cleanupError; },
    logger: { error: (...args) => errors.push(args.join(' ')) },
  }),
  error => error === cleanupError,
);
assert.equal(errors.length, 1);
assert.match(errors[0], /Chromium profile cleanup/i);
assert.match(errors[0], /ENOTEMPTY/);

const moduleUrl = new URL('./verify-uis.mjs', import.meta.url).href;
const fatalCleanup = spawnSync(process.execPath, [
  '--input-type=module',
  '--eval',
  `import { cleanupChromiumProfile } from ${JSON.stringify(moduleUrl)};
const error = Object.assign(new Error('directory not empty'), { code: 'ENOTEMPTY' });
await cleanupChromiumProfile('/tmp/tim-ui-profile', { rmProfile: async () => { throw error; } });`,
], { encoding: 'utf8' });

assert.notEqual(fatalCleanup.status, 0, 'exhausted profile cleanup must exit nonzero');
assert.match(fatalCleanup.stderr, /Chromium profile cleanup/i);
assert.match(fatalCleanup.stderr, /ENOTEMPTY/);

console.log('PASS Chromium profile cleanup retries and failure semantics');
