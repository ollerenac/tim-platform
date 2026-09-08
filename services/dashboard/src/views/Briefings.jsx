import { useState, useEffect, useRef } from 'react';
import { listBriefings, postGenerate, getBriefing, pdfUrl } from '../api';

export default function Briefings() {
  const [briefings, setBriefings] = useState([]);
  const [generating, setGenerating] = useState(false);
  const [periodHours, setPeriodHours] = useState(24);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  useEffect(() => {
    listBriefings()
      .then(setBriefings)
      .catch(() => setError('Could not load data — briefing-generator unreachable.'));
    return () => clearInterval(pollRef.current);
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const { briefing_id } = await postGenerate(periodHours);
      pollRef.current = setInterval(async () => {
        try {
          const b = await getBriefing(briefing_id);
          if (b.status === 'done' || b.status === 'error') {
            clearInterval(pollRef.current);
            setGenerating(false);
            listBriefings().then(setBriefings);
          }
        } catch {
          clearInterval(pollRef.current);
          setGenerating(false);
          setError('Lost connection while waiting for briefing. Check status and retry.');
        }
      }, 3000);
    } catch {
      setError('Generation failed. Please try again.');
      setGenerating(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px' }}>
        <select
          value={periodHours}
          onChange={e => setPeriodHours(parseInt(e.target.value, 10))}
          disabled={generating}
        >
          <option value={24}>Last 24 hours</option>
          <option value={72}>Last 72 hours</option>
          <option value={168}>Last 7 days</option>
        </select>
        <button
          className="btn-primary"
          onClick={handleGenerate}
          disabled={generating}
          style={generating ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
        >
          Generate Briefing
        </button>
        {generating && (
          <span style={{ color: 'var(--color-muted)', fontSize: '14px' }}>Generating…</span>
        )}
      </div>

      {error && (
        <p style={{ color: 'var(--color-destructive)', fontSize: '14px' }}>{error}</p>
      )}

      {briefings.length === 0 ? (
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '8px' }}>No briefings yet</h2>
          <p style={{ color: 'var(--color-muted)', fontSize: '14px' }}>
            Select a time period and click Generate Briefing to create your first summary.
          </p>
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <tbody>
            {briefings.map(b => (
              <tr key={b.briefing_id} style={{ borderBottom: '1px solid var(--color-border)' }}>
                <td style={{ padding: '8px', fontSize: '12px', color: 'var(--color-muted)' }}>
                  {b.created_at}
                </td>
                <td style={{ padding: '8px', fontSize: '14px' }}>{b.period_hours}h</td>
                <td style={{ padding: '8px', fontSize: '14px' }}>{b.status}</td>
                <td style={{ padding: '8px' }}>
                  {b.status === 'done' && (
                    <a
                      href={pdfUrl(b.briefing_id)}
                      download
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ fontSize: '14px', color: 'var(--color-accent)' }}
                    >
                      Download PDF
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
