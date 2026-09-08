// ponytail: relative paths — nginx proxies /api/* to backends over Docker internal network
const FEED_URL     = '/api/feeds';
const SEARCH_URL   = '/api/semantic';
const BRIEFING_URL = '/api/briefings';
const EXTRACTOR_URL = '/api/extractor';

// r.ok guard — throws on non-2xx so callers see a rejection instead of a malformed object
const j = r => { if (!r.ok) throw new Error(r.status); return r.json(); };

// 10s timeout so a hung backend can't leave the 30s pollers' requests pending forever
const fetchT = (url, opts = {}) => fetch(url, { signal: AbortSignal.timeout(10000), ...opts });

export const getFeedsStatus = () =>
  fetchT(`${FEED_URL}/feeds/status`).then(j);

export const getAlerts = () =>
  fetchT(`${FEED_URL}/feeds/alerts`).then(j);

export const getStats = () =>
  fetchT(`${BRIEFING_URL}/stats`).then(j);

// GET with query params — semantic-engine/main.py line 41 confirms @app.get("/search"), NOT POST
export const searchIOCs = (query, n = 10) =>
  fetchT(`${SEARCH_URL}/search?q=${encodeURIComponent(query)}&n_results=${n}`)
    .then(j);

export const postGenerate = (periodHours) =>
  fetchT(`${BRIEFING_URL}/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ period_hours: periodHours }),
  }).then(j);

export const getBriefing = (id) =>
  fetchT(`${BRIEFING_URL}/briefings/${id}`).then(j);

export const listBriefings = () =>
  fetchT(`${BRIEFING_URL}/briefings`).then(j);

// Returns URL string — not a fetch call; used as <a href={pdfUrl(id)} download>
export const pdfUrl = (id) => `${BRIEFING_URL}/briefings/${id}/pdf`;

export const getFeedsRecent = (limit = 200) =>
  fetchT(`${FEED_URL}/feeds/recent?limit=${limit}`).then(j);

export const getRecentDocs = () =>
  fetchT(`${EXTRACTOR_URL}/recent`).then(j);

export const getExtractorStats = () =>
  fetchT(`${EXTRACTOR_URL}/stats`).then(j);

export const getSemanticStats = () =>
  fetchT(`${SEARCH_URL}/stats`).then(j);

export const getCVEStats = () =>
  fetchT(`${BRIEFING_URL}/cve/stats`).then(j);

export const getCollectorStatus = () =>
  fetchT(`${EXTRACTOR_URL}/collector/status`).then(j);

export const getConnectorsStatus = () =>
  fetchT(`${FEED_URL}/connectors/status`).then(j);
