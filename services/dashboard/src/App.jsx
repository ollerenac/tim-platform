import { useState } from 'react';
import './App.css';
import Overview from './views/Overview';
import Briefings from './views/Briefings';
import Alerts from './views/Alerts';
import IngestMonitor from './views/IngestMonitor';

const TABS = ['Overview', 'Briefings', 'Alerts', 'Ingestion Monitor'];
const VIEWS = { Overview, Briefings, Alerts, 'Ingestion Monitor': IngestMonitor };

const VIEW_META = {
  Overview: {
    eyebrow: 'SOC Dashboard',
    title: 'Threat Intelligence Management',
    description: 'Operational view of feed health, IOC volume, and ATT&CK context.',
  },
  Briefings: {
    eyebrow: 'Reporting',
    title: 'Briefings',
    description: 'Generate and review executive intelligence summaries from local OpenCTI data.',
  },
  Alerts: {
    eyebrow: 'Detection Queue',
    title: 'Alerts',
    description: 'Review high-confidence IOCs promoted from the structured feed pipeline.',
  },
  'Ingestion Monitor': {
    eyebrow: 'Pipeline',
    title: 'Ingestion Monitor',
    description: 'Track feed ingestion, document extraction, and source collectors.',
  },
};

export default function App() {
  const [tab, setTab] = useState('Overview');
  const View = VIEWS[tab];
  const meta = VIEW_META[tab];

  return (
    <div className="app-shell">
      <aside className="app-sidebar" aria-label="Primary navigation">
        <div className="brand-block">
          <span className="brand-kicker">TIM</span>
          <span className="brand-name">SOC Console</span>
        </div>
        <nav className="side-nav">
          {TABS.map(t => (
            <button
              key={t}
              type="button"
              className={tab === t ? 'side-nav-item active' : 'side-nav-item'}
              onClick={() => setTab(t)}
              aria-current={tab === t ? 'page' : undefined}
            >
              <span>{t}</span>
            </button>
          ))}
        </nav>
      </aside>

      <div className="app-main">
        <header className="object-header">
          <div className="breadcrumbs">
            <span>TIM</span>
            <span>/</span>
            <span>{meta.eyebrow}</span>
          </div>
          <div className="title-row">
            <div>
              <h1>{meta.title}</h1>
              <p>{meta.description}</p>
            </div>
            <div className="header-badges" aria-label="Current system scope">
              <span>Local CTI</span>
              <span>OpenCTI</span>
              <span>Air-gapped</span>
            </div>
          </div>
        </header>

        <main className="main-content">
          <View />
        </main>
      </div>
    </div>
  );
}
