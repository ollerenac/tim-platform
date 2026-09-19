import { useState, useEffect, useRef } from 'react';
import {
  getFeedsStatus,
  getExtractorStats,
  getCVEStats,
  getFeedsRecent,
  getRecentDocs,
  getCollectorStatus,
} from '../api';

function pillStatus(data, key) {
  if (!data) return 'status-never_run';
  return data[key] === 'ok' ? 'status-ok' : 'status-never_run';
}

function confClass(conf) {
  if (conf >= 75) return 'status-ok';
  if (conf >= 55) return 'status-stale';
  return 'status-never_run';
}

export default function IngestMonitor() {
  const [feedsData,    setFeedsData]    = useState(null);
  const [extractorData,setExtractorData]= useState(null);
  const [cveData,      setCveData]      = useState(null);
  const [iocs,         setIocs]         = useState([]);
  const [docs,         setDocs]         = useState([]);
  const [collectorData,setCollectorData]= useState(null);
  const iocTopRef = useRef(null);

  useEffect(() => {
    // ponytail: per-fetch isolation — one down service doesn't freeze all dashboard state
    const safe = p => p.catch(() => null);
    const load = () =>
      Promise.all([
        safe(getFeedsStatus()).then(d    => d && setFeedsData(d)),
        safe(getExtractorStats()).then(d => d && setExtractorData(d)),
        safe(getCVEStats()).then(d       => d && setCveData(d)),
        safe(getFeedsRecent(200)).then(d => d && setIocs(d.iocs || [])),
        safe(getRecentDocs()).then(d     => d && setDocs(d.docs || [])),
        safe(getCollectorStatus()).then(d => d && setCollectorData(d)),
      ]);

    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  // Auto-scroll to TOP of IOC log when new data arrives (newest entry is at top)
  // ponytail: Pitfall 4 — sentinel div is ABOVE the table, not attached to the last row
  useEffect(() => {
    iocTopRef.current?.scrollIntoView({ block: 'start' });
  }, [iocs]);

  // Derive feed health pill
  const feeds = feedsData?.feeds || [];
  const feedsStatus =
    feeds.every(f => f.status === 'ok') ? 'status-ok' :
    feeds.some(f  => f.status === 'ok') ? 'status-stale' :
    'status-never_run';

  // OpenCTI status derived from feed success (OpenCTI /health returns 401)
  const openctiStatus = feeds.some(f => f.status === 'ok') ? 'status-ok' : 'status-never_run';

  // D-10: dynamic staleness — custom helper required; /collector/status has no 'status' key
  function collectorPillCls(data) {
    if (!data || !data.last_run) return 'status-never_run';
    const minHours = Math.min(...(data.sources || []).map(s => s.poll_interval_hours ?? 24));
    const ageHours = (Date.now() - new Date(data.last_run).getTime()) / 3_600_000;
    if (ageHours > minHours * 2) return 'status-never_run';
    if (ageHours > minHours * 1.5) return 'status-stale';
    return 'status-ok';
  }

  // D-09: sum new_found across all sources for the pill label
  const totalNew = (collectorData?.sources || []).reduce((s, x) => s + (x.new_found || 0), 0);

  const pills = [
    { label: 'Feeds',          cls: feedsStatus },
    { label: 'OpenCTI',        cls: openctiStatus }, // derived from feed success (OpenCTI /health returns 401)
    { label: 'Extractor',      cls: pillStatus(extractorData, 'status') },
    { label: 'CVE',            cls: pillStatus(cveData,       'status') },
    { label: collectorData ? `Collector (${totalNew} new)` : 'Collector (–)', cls: collectorPillCls(collectorData) },
  ];

  return (
    <div className="card">
      <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '16px' }}>Ingestion Monitor</h2>



      {/* Pipeline health strip */}
      <div style={{ display: 'flex', gap: '24px', marginBottom: '24px', flexWrap: 'wrap' }}>
        {pills.map(p => (
          <div key={p.label} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`status-dot ${p.cls}`} />
            <span style={{ fontSize: '13px', fontWeight: 500 }}>{p.label}</span>
          </div>
        ))}
      </div>

      {/* IOC log */}
      <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '8px' }}>Live Ingestion</h3>
      {/* ponytail: sentinel div ABOVE table — scrollIntoView scrolls to newest (top), not oldest (bottom) */}
      <div ref={iocTopRef} />
      <div style={{ overflowY: 'auto', maxHeight: '400px', marginBottom: '24px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ color: 'var(--color-muted)', textAlign: 'left' }}>
              <th style={{ padding: '6px 8px' }}>Ingested</th>
              <th style={{ padding: '6px 8px' }}>Indicator</th>
              <th style={{ padding: '6px 8px' }}>OpenCTI ID</th>
              <th style={{ padding: '6px 8px' }}>Type</th>
              <th style={{ padding: '6px 8px' }}>Feed</th>
              <th style={{ padding: '6px 8px' }}>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {iocs.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '12px 8px', color: 'var(--color-muted)' }}>
                  No IOCs yet — waiting for feed run
                </td>
              </tr>
            ) : (
              iocs.map((ioc, i) => (
                <tr key={i} style={{ borderTop: '1px solid var(--color-border)' }}>
                  <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                    {new Date(ioc.ingested_at || ioc.ts).toLocaleTimeString('en-GB', { hour12: false })}
                  </td>
                  <td style={{
                    padding: '6px 8px',
                    maxWidth: '240px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}>
                    {ioc.value}
                  </td>
                  <td title={ioc.opencti_standard_id || ioc.stix_id || ''} style={{
                    padding: '6px 8px',
                    maxWidth: '180px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                    fontSize: '12px',
                  }}>
                    {ioc.opencti_standard_id || ioc.stix_id || '—'}
                  </td>
                  <td style={{ padding: '6px 8px' }}>{ioc.type}</td>
                  <td style={{ padding: '6px 8px' }}>{ioc.feed}</td>
                  <td style={{ padding: '6px 8px' }}>
                    <span className={confClass(ioc.confidence)}
                          style={{ fontSize: '12px', fontWeight: 600, padding: '1px 5px', borderRadius: '3px' }}>
                      {ioc.confidence}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Document pipeline */}
      <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '8px' }}>Document Pipeline</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
        <thead>
          <tr style={{ color: 'var(--color-muted)', textAlign: 'left' }}>
            <th style={{ padding: '6px 8px' }}>Time</th>
            <th style={{ padding: '6px 8px' }}>Filename</th>
            <th style={{ padding: '6px 8px' }}>IOCs</th>
            <th style={{ padding: '6px 8px' }}>Status</th>
          </tr>
        </thead>
        <tbody>
          {docs.length === 0 ? (
            <tr>
              <td colSpan={4} style={{ padding: '12px 8px', color: 'var(--color-muted)' }}>
                No documents processed yet
              </td>
            </tr>
          ) : (
            docs.map((doc, i) => (
              <tr key={i} style={{ borderTop: '1px solid var(--color-border)' }}>
                <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>
                  {new Date(doc.ingested_at).toLocaleTimeString('en-GB', { hour12: false })}
                </td>
                <td style={{ padding: '6px 8px' }}>{doc.filename}</td>
                <td style={{ padding: '6px 8px' }}>{doc.ioc_count}</td>
                <td style={{ padding: '6px 8px', color: doc.status?.startsWith('error:') ? 'var(--color-warning)' : 'inherit' }}>
                  {doc.status}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
