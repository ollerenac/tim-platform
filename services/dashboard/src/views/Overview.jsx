import { useState, useEffect } from 'react';
import { getFeedsStatus, getStats, getConnectorsStatus } from '../api';

function statusClass(feed) {
  if (feed.status === 'ok') return 'status-ok';
  if (feed.status === 'error') return 'status-error';
  if (feed.status === 'never_run') return 'status-never_run';
  // stale: last_run exists and more than 1 hour ago
  if (feed.last_run && (new Date() - new Date(feed.last_run)) > 3600000) return 'status-stale';
  return 'status-never_run';
}

function connectorStatusClass(c) {
  if (!c.active) return 'status-error';
  if (!c.last_run) return 'status-never_run';
  // 48h threshold — connectors run on daily-ish schedules, unlike hourly feeds
  if ((new Date() - new Date(c.last_run)) > 48 * 3600000) return 'status-stale';
  return 'status-ok';
}

export default function Overview() {
  const [feeds, setFeeds] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const load = () =>
      Promise.all([
        getFeedsStatus().then(d => setFeeds(d.feeds || [])),
        getStats().then(setStats),
        // per-call catch — a connector-endpoint failure must not hide the feed boxes
        getConnectorsStatus().then(d => setConnectors(d.connectors || [])).catch(() => setConnectors([])),
      ]).catch(() => setError('Could not load data — feed-orchestrator unreachable. Retry in 30s.'));

    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id); // cleanup — prevents stale interval on unmount
  }, []);

  if (error) {
    return <p style={{ color: 'var(--color-destructive)', fontSize: '14px' }}>{error}</p>;
  }

  return (
    <div>
      {feeds.length === 0 ? (
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '8px' }}>No feeds configured</h2>
          <p style={{ color: 'var(--color-muted)', fontSize: '14px' }}>
            Feed orchestrator returned no data. Check service health.
          </p>
        </div>
      ) : (
        <div className="feed-grid">
          {feeds.map(feed => (
            <div key={feed.name} className="card">
              <span style={{ fontSize: '12px', fontWeight: 600 }}>{feed.name}</span>
              <span style={{ color: 'var(--color-muted)', fontSize: '14px', display: 'block', marginTop: '4px' }}>
                {feed.last_run || 'Never'}
              </span>
              <div style={{ fontSize: '28px', fontWeight: 600, margin: '8px 0' }}>{feed.ioc_count}</div>
              <span className={`status-dot ${statusClass(feed)}`} />
            </div>
          ))}
        </div>
      )}

      {connectors.length > 0 && (
        <div style={{ marginTop: '24px' }}>
          <span style={{ fontSize: '12px', fontWeight: 600 }}>OpenCTI Connectors</span>
          <div className="feed-grid" style={{ marginTop: '8px' }}>
            {connectors.map(c => (
              <div key={c.name} className="card">
                <span style={{ fontSize: '12px', fontWeight: 600 }}>{c.name}</span>
                <span style={{ color: 'var(--color-muted)', fontSize: '14px', display: 'block', marginTop: '4px' }}>
                  {c.last_run || 'Never'}
                </span>
                <span className={`status-dot ${connectorStatusClass(c)}`} />
              </div>
            ))}
          </div>
        </div>
      )}

      {stats && (
        <div className="feed-grid" style={{ marginTop: '24px' }}>
          <div className="card">
            <span style={{ fontSize: '12px', fontWeight: 600 }}>IOC count (24h)</span>
            <div style={{ fontSize: '28px', fontWeight: 600, marginTop: '8px' }}>{stats.ioc_count_24h}</div>
          </div>
          <div className="card">
            <span style={{ fontSize: '12px', fontWeight: 600 }}>Top ATT&CK Techniques</span>
            <ol style={{ marginTop: '8px', paddingLeft: '20px' }}>
              {(stats.top_techniques || []).map(item => (
                <li key={item.id || item.name} style={{ fontSize: '14px', marginBottom: '4px' }}>
                  {item.id || '—'} &mdash; {item.name}{item.count != null ? ` (${item.count})` : ''}
                </li>
              ))}
            </ol>
          </div>
        </div>
      )}
    </div>
  );
}
