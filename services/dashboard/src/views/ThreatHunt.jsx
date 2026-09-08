import { useState } from 'react';
import { searchIOCs } from '../api';

export default function ThreatHunt() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState(null);
  const [searched, setSearched] = useState(false);

  const search = async () => {
    if (!query || query.length > 500) return; // mirrors semantic-engine server-side 400 (T-06-03-03)
    setSearching(true);
    setError(null);
    try {
      const data = await searchIOCs(query);
      setResults(data.results || []);
      setSearched(true);
    } catch {
      setError('Could not load data — semantic-engine unreachable. Retry in 30s.');
    } finally {
      setSearching(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') search();
  };

  return (
    <div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search threats by description, IOC, or behaviour…"
          style={{ flex: 1 }}
        />
        <button className="btn-primary" onClick={search}>Search</button>
      </div>

      {error && (
        <p style={{ color: 'var(--color-destructive)', fontSize: '14px' }}>{error}</p>
      )}

      {searching && (
        <p style={{ color: 'var(--color-muted)', fontSize: '14px' }}>Searching…</p>
      )}

      {!searching && searched && results.length === 0 && (
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '8px' }}>No results found</h2>
          <p style={{ color: 'var(--color-muted)', fontSize: '14px' }}>
            Try a broader query or wait for more IOCs to be indexed.
          </p>
        </div>
      )}

      {!searching && results.length > 0 && (
        <ol style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {results.map((result, i) => (
            <li key={i}>
              {/* ponytail: scheme guard at trust boundary — API response → href */}
              <a
                href={/^https?:\/\//.test(result.opencti_url) ? result.opencti_url : undefined}
                target="_blank"
                rel="noopener noreferrer"
                style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 0', cursor: 'pointer', textDecoration: 'none', color: 'inherit' }}
              >
                <span className="score-badge">{Number(result.score ?? 0).toFixed(2)}</span>
                <span style={{ fontSize: '14px' }}>{result.value}</span>
                <span style={{ fontSize: '12px', color: 'var(--color-muted)' }}>{result.ioc_type}</span>
              </a>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
