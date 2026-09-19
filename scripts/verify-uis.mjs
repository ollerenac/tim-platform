#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = new URL('..', import.meta.url).pathname;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const cleanupLogger = {
  error: message => writeSync(process.stderr.fd, `${message}\n`),
};

export async function cleanupChromiumProfile(
  profile,
  { rmProfile = rm, logger = cleanupLogger } = {},
) {
  try {
    await rmProfile(profile, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 25,
    });
  } catch (error) {
    await logger.error(
      `[tim-check] Chromium profile cleanup failed (${error.code || 'UNKNOWN'}): ${error.message}`,
    );
    throw error;
  }
}

function describeKibanaState(state) {
  const text = String(state?.text || '').replace(/\s+/g, ' ').trim().slice(0, 240);
  return `title=${JSON.stringify(state?.title || '')}; url=${state?.url || 'unknown'}; body=${JSON.stringify(text)}`;
}

export async function ensureKibanaApplication({
  readState,
  reload,
  logger = console,
  sleepFn = sleep,
  timeoutMs = 180000,
  pollIntervalMs = 250,
  now = Date.now,
}) {
  const deadline = now() + timeoutMs;
  let refreshed = false;
  let state;

  while (now() < deadline) {
    state = await readState();
    const text = String(state?.text || '');
    const ready = String(state?.title || '').includes('Elastic') &&
      text.includes('Welcome home') &&
      !text.includes('Kibana server is not ready yet');
    if (ready) return { refreshed, state };

    const requestsRefresh = text.includes('Refresh the page') ||
      text.includes('Try refreshing the page');
    if (requestsRefresh) {
      if (refreshed) {
        throw new Error(`Kibana still requests a page refresh after one retry; ${describeKibanaState(state)}`);
      }
      refreshed = true;
      logger.warn('  WARN Kibana requested a page refresh; retrying once');
      await reload();
    }

    await sleepFn(pollIntervalMs);
  }

  throw new Error(`Kibana application timed out; ${describeKibanaState(state)}`);
}

function loadEnv() {
  const text = requireText(join(ROOT, '.env'));
  return Object.fromEntries(text.split(/\r?\n/).flatMap(raw => {
    const line = raw.trim();
    if (!line || line.startsWith('#') || !line.includes('=')) return [];
    const at = line.indexOf('=');
    return [[line.slice(0, at).trim(), line.slice(at + 1).trim().replace(/^(['"])(.*)\1$/, '$2')]];
  }));
}

function requireText(path) {
  if (!existsSync(path)) throw new Error(`missing file: ${path}`);
  return readFileSync(path, 'utf8');
}

function chromeBinary() {
  const choices = [
    process.env.CHROME_BIN,
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
  ].filter(Boolean);
  const found = choices.find(existsSync);
  if (!found) throw new Error('Google Chrome/Chromium is required for UI verification');
  return found;
}

class CDP {
  constructor(url) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    this.socket = new WebSocket(url);
  }

  async connect() {
    await new Promise((resolve, reject) => {
      this.socket.addEventListener('open', resolve, { once: true });
      this.socket.addEventListener('error', reject, { once: true });
    });
    this.socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
        return;
      }
      for (const listener of this.listeners.get(message.method) || []) listener(message.params || {});
    });
  }

  on(method, listener) {
    const listeners = this.listeners.get(method) || [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
  }

  send(method, params = {}) {
    const id = this.nextId++;
    this.socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP timeout: ${method}`));
      }, 120000);
      this.pending.set(id, {
        resolve: value => { clearTimeout(timer); resolve(value); },
        reject: error => { clearTimeout(timer); reject(error); },
      });
    });
  }

  close() {
    this.socket.close();
  }
}

async function waitFor(label, predicate, timeout = 90000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      if (await predicate()) return;
    } catch (error) {
      lastError = error;
    }
    await sleep(250);
  }
  throw new Error(`${label} timed out${lastError ? `: ${lastError.message}` : ''}`);
}

async function evaluate(cdp, expression, awaitPromise = false) {
  const result = await cdp.send('Runtime.evaluate', {
    expression,
    awaitPromise,
    returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || 'browser evaluation failed');
  return result.result.value;
}

async function waitForExpression(cdp, label, expression, timeout) {
  await waitFor(label, () => evaluate(cdp, `Boolean(${expression})`), timeout);
}

async function navigate(cdp, url) {
  const result = await cdp.send('Page.navigate', { url });
  // Chrome can report ERR_ABORTED when an authenticated navigation replaces its
  // initial challenge/redirect request. The resulting document is authoritative.
  if (result.errorText && result.errorText !== 'net::ERR_ABORTED') {
    throw new Error(`navigation to ${url} failed: ${result.errorText}`);
  }
  await waitForExpression(cdp, `${url} document`, "document.readyState === 'complete'", 120000);
}

async function clickTab(cdp, title) {
  const clicked = await evaluate(cdp, `(() => {
    const button = [...document.querySelectorAll('button')].find(node => node.textContent.trim() === ${JSON.stringify(title)});
    if (!button) return false;
    button.click();
    return true;
  })()`);
  if (!clicked) throw new Error(`dashboard tab not found: ${title}`);
  await waitForExpression(
    cdp,
    `${title} view`,
    `document.querySelector('h1')?.textContent.trim() === ${JSON.stringify(title === 'Overview' ? 'Threat Intelligence Management' : title)}`,
    15000,
  );
}

function responseFor(responses, path) {
  return [...responses.entries()].find(([url]) => new URL(url).pathname === path)?.[1];
}

async function requireResponse(responses, path, timeout = 120000) {
  await waitFor(`${path} response`, () => responseFor(responses, path) === 200, timeout);
}

async function screenshotIsNonBlank(cdp, label) {
  const capture = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  const bytes = Buffer.from(capture.data, 'base64');
  if (bytes.length < 15000) throw new Error(`${label} screenshot is suspiciously blank (${bytes.length} bytes)`);
  return bytes;
}

async function main() {
  const env = loadEnv();
  if (!env.KIBANA_USER || !env.KIBANA_PASSWORD) {
    throw new Error('KIBANA_USER and KIBANA_PASSWORD are required in .env');
  }

  const profile = await mkdtemp(join(tmpdir(), 'tim-ui-check-'));
  const stderr = [];
  const chrome = spawn(chromeBinary(), [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-crash-reporter',
    '--no-first-run',
    '--no-default-browser-check',
    '--ignore-certificate-errors',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    '--window-size=1440,1000',
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  chrome.stderr.on('data', chunk => {
    stderr.push(chunk.toString());
    if (stderr.length > 20) stderr.shift();
  });

  let cdp;
  let failureScreenshot;
  let functionalError;
  try {
    const portFile = join(profile, 'DevToolsActivePort');
    await waitFor('Chrome DevTools endpoint', () => existsSync(portFile), 30000);
    const [port] = (await readFile(portFile, 'utf8')).split(/\r?\n/);
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const page = pages.find(target => target.type === 'page' && target.url === 'about:blank')
      || pages.find(target => target.type === 'page');
    if (!page) throw new Error('Chrome did not expose a page target');
    cdp = new CDP(page.webSocketDebuggerUrl);
    await cdp.connect();
    cdp.on('Fetch.requestPaused', ({ requestId }) => {
      cdp.send('Fetch.continueRequest', { requestId }).catch(() => {});
    });
    cdp.on('Fetch.authRequired', ({ requestId }) => {
      cdp.send('Fetch.continueWithAuth', {
        requestId,
        authChallengeResponse: {
          response: 'ProvideCredentials',
          username: env.KIBANA_USER,
          password: env.KIBANA_PASSWORD,
        },
      }).catch(() => {});
    });
    await Promise.all([
      cdp.send('Page.enable'),
      cdp.send('Runtime.enable'),
      cdp.send('Network.enable'),
      cdp.send('Fetch.enable', { handleAuthRequests: true }),
    ]);

    const responses = new Map();
    const failures = [];
    cdp.on('Network.responseReceived', ({ response, type }) => {
      responses.set(response.url, response.status);
      const parsed = new URL(response.url);
      const host = parsed.hostname;
      const expectedNoSecurityProfile = response.status === 404 &&
        parsed.pathname === '/internal/security/user_profile';
      if ((host === 'localhost' || host === '127.0.0.1') && response.status >= 400 &&
          !expectedNoSecurityProfile && ['Document', 'Script', 'Stylesheet', 'XHR', 'Fetch'].includes(type)) {
        failures.push(`${response.status} ${response.url}`);
      }
    });
    cdp.on('Network.loadingFailed', event => {
      if (!event.canceled && !String(event.errorText).includes('ERR_ABORTED')) {
        failures.push(`${event.errorText} ${event.blockedReason || ''}`.trim());
      }
    });

    console.log('[tim-check] Chromium SOC Dashboard flow');
    await navigate(cdp, 'https://localhost/');
    await requireResponse(responses, '/api/feeds/feeds/status');
    await requireResponse(responses, '/api/briefings/stats');
    await requireResponse(responses, '/api/feeds/connectors/status');
    await waitForExpression(
      cdp,
      'SOC Overview data',
      "document.querySelectorAll('.feed-grid .card').length > 0 && !document.body.innerText.includes('Could not load')",
      120000,
    );

    await clickTab(cdp, 'Briefings');
    await requireResponse(responses, '/api/briefings/briefings');
    await waitForExpression(cdp, 'Briefings view', "!document.body.innerText.includes('Could not load')", 30000);

    await clickTab(cdp, 'Alerts');
    await requireResponse(responses, '/api/feeds/feeds/alerts');
    await waitForExpression(cdp, 'Alerts view', "!document.body.innerText.includes('Loading') && !document.body.innerText.includes('Could not load')", 30000);

    await clickTab(cdp, 'Ingestion Monitor');
    for (const path of [
      '/api/extractor/stats',
      '/api/briefings/cve/stats',
      '/api/feeds/feeds/recent',
      '/api/extractor/recent',
      '/api/extractor/collector/status',
    ]) await requireResponse(responses, path);
    await waitForExpression(cdp, 'Ingestion Monitor view', "document.body.innerText.includes('Live Ingestion')", 30000);
    await screenshotIsNonBlank(cdp, 'SOC Dashboard');

    if (failures.length) throw new Error(`SOC browser resources failed: ${[...new Set(failures)].slice(0, 5).join('; ')}`);
    console.log('  PASS authenticated React UI, four views, and proxied APIs rendered');

    responses.clear();
    failures.length = 0;
    console.log('[tim-check] Chromium Kibana flow');
    await navigate(cdp, 'http://localhost:5602/app/home');
    await ensureKibanaApplication({
      readState: () => evaluate(cdp, `({
        title: document.title,
        url: location.href,
        text: document.body?.innerText || '',
      })`),
      reload: async () => {
        responses.clear();
        failures.length = 0;
        await cdp.send('Page.reload', { ignoreCache: true });
        await waitForExpression(cdp, 'Kibana refreshed document', "document.readyState === 'complete'", 120000);
      },
    });
    const status = await evaluate(cdp, `(async () => {
      const response = await fetch('/api/status');
      return { http: response.status, body: await response.json() };
    })()`, true);
    const level = status?.body?.status?.overall?.level;
    if (status.http !== 200 || level !== 'available') throw new Error(`Kibana browser status is ${status.http}/${level}`);
    await screenshotIsNonBlank(cdp, 'Kibana');
    if (failures.length) throw new Error(`Kibana browser resources failed: ${[...new Set(failures)].slice(0, 5).join('; ')}`);
    console.log('  PASS authenticated Kibana application rendered with available browser status');
  } catch (error) {
    if (cdp) {
      try {
        const capture = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
        failureScreenshot = join(tmpdir(), `tim-ui-failure-${Date.now()}.png`);
        await writeFile(failureScreenshot, Buffer.from(capture.data, 'base64'));
      } catch {}
    }
    const detail = stderr.join('').split(/\r?\n/).filter(Boolean).slice(-3).join(' | ');
    functionalError = new Error(`${error.message}${failureScreenshot ? `; screenshot: ${failureScreenshot}` : ''}${detail ? `; Chrome: ${detail}` : ''}`);
  } finally {
    cdp?.close();
    const exited = new Promise(resolve => chrome.once('exit', resolve));
    chrome.kill('SIGTERM');
    await Promise.race([exited, sleep(1000)]);
    if (chrome.exitCode === null) {
      chrome.kill('SIGKILL');
      await exited;
    }
    try {
      await cleanupChromiumProfile(profile);
    } catch (error) {
      if (!functionalError) throw error;
    }
  }

  if (functionalError) throw functionalError;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(`  FAIL ${error.message}`);
    process.exitCode = 1;
  });
}
