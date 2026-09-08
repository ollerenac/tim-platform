import { useState, useEffect } from 'react';
import { getAlerts } from '../api';

const SEVERITY = score =>
  score >= 65 ? { label: 'HIGH', color: 'var(--color-destructive)' } :
  score >= 55 ? { label: 'MED',  color: '#f59e0b' } :
                { label: 'LOW',  color: 'var(--color-muted)' };

export default function Alerts() {
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const load = () =>
      getAlerts()
        .then(setData)
        .catch(() => setError('Could not load alerts — feed-orchestrator unreachable.'));
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  if (error) return <p style={{ color: 'var(--color-destructive)', fontSize: '14px' }}>{error}</p>;
  if (!data)  return <p style={{ color: 'var(--color-muted)', fontSize: '14px' }}>Loading…</p>;

  const { alerts, threshold } = data;

  return (
    <div>
      <p style={{ color: 'var(--color-muted)', fontSize: '13px', marginBottom: '16px' }}>
        High-confidence IOCs (score ≥ {threshold}) — newest first, last 100
      </p>

      {alerts.length === 0 ? (
        <p style={{ color: 'var(--color-muted)', fontSize: '14px' }}>
          No alerts yet — they appear here when feeds ingest IOCs scoring ≥ {threshold}.
        </p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--color-border)' }}>
              <th style={{ padding: '6px 8px', fontWeight: 600 }}>Score</th>
              <th style={{ padding: '6px 8px', fontWeight: 600 }}>Type</th>
              <th style={{ padding: '6px 8px', fontWeight: 600 }}>IOC</th>
              <th style={{ padding: '6px 8px', fontWeight: 600 }}>Feed</th>
              <th style={{ padding: '6px 8px', fontWeight: 600 }}>Time (UTC)</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a, i) => {
              const sev = SEVERITY(a.confidence);
              return (
                <tr key={i} style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <td style={{ padding: '6px 8px', color: sev.color, fontWeight: 700 }}>
                    {a.confidence} <span style={{ fontSize: '11px' }}>{sev.label}</span>
                  </td>
                  <td style={{ padding: '6px 8px', color: 'var(--color-muted)' }}>{a.type}</td>
                  <td style={{ padding: '6px 8px', fontFamily: 'monospace', wordBreak: 'break-all' }}>{a.value}</td>
                  <td style={{ padding: '6px 8px' }}>{a.feed}</td>
                  <td style={{ padding: '6px 8px', color: 'var(--color-muted)' }}>
                    {(() => { const d = new Date(a.ts); return isNaN(d) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19); })()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
