#!/usr/bin/env node

import assert from 'node:assert/strict';

import { ensureKibanaApplication } from './verify-uis.mjs';

const ready = {
  title: 'Home - Elastic',
  url: 'http://localhost:5602/app/home#/',
  text: 'Home Welcome home Management Dev Tools Stack Management',
};
const refreshError = {
  title: '',
  url: 'http://localhost:5602/app/home',
  text: 'Refresh the page This should resolve any issues loading the page.',
};
const fetchError = {
  title: 'Elastic',
  url: 'http://localhost:5602/app/home',
  text: 'Something went wrong Try refreshing the page. Failed to fetch Version: 8.15.0',
};

{
  const states = [refreshError, ready];
  const warnings = [];
  let reloads = 0;
  const result = await ensureKibanaApplication({
    readState: async () => states.shift() || ready,
    reload: async () => { reloads += 1; },
    logger: { warn: message => warnings.push(message) },
    sleepFn: async () => {},
  });

  assert.deepEqual(result, { refreshed: true, state: ready });
  assert.equal(reloads, 1);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /Kibana requested a page refresh/i);
}

{
  const states = [fetchError, ready];
  let reloads = 0;
  const result = await ensureKibanaApplication({
    readState: async () => states.shift() || ready,
    reload: async () => { reloads += 1; },
    logger: { warn: () => {} },
    sleepFn: async () => {},
  });
  assert.deepEqual(result, { refreshed: true, state: ready });
  assert.equal(reloads, 1);
}

{
  let reloads = 0;
  await assert.rejects(
    ensureKibanaApplication({
      readState: async () => refreshError,
      reload: async () => { reloads += 1; },
      logger: { warn: () => {} },
      sleepFn: async () => {},
    }),
    error => {
      assert.match(error.message, /still requests a page refresh after one retry/i);
      assert.match(error.message, /http:\/\/localhost:5602\/app\/home/);
      return true;
    },
  );
  assert.equal(reloads, 1);
}

{
  let reloads = 0;
  const result = await ensureKibanaApplication({
    readState: async () => ready,
    reload: async () => { reloads += 1; },
    logger: { warn: () => {} },
    sleepFn: async () => {},
  });
  assert.deepEqual(result, { refreshed: false, state: ready });
  assert.equal(reloads, 0);
}

console.log('PASS Kibana refresh recovery and terminal error semantics');
