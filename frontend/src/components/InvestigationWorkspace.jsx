import React, { useState, useEffect } from 'react';
import { fetchHealthStatus } from '../services/api';
import IncidentOverview from './IncidentOverview';
import AttackInvestigation from './AttackInvestigation';
import ThreatIntelligence from './ThreatIntelligence';
import AIInvestigationResponse from './AIInvestigationResponse';

export default function InvestigationWorkspace({ onBackToLanding }) {
  const [health, setHealth] = useState({ connected: false, loading: true });
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncidentData, setSelectedIncidentData] = useState(null);

  const checkBackendHealth = async () => {
    const res = await fetchHealthStatus();
    setHealth(res);
  };

  useEffect(() => {
    checkBackendHealth();
  }, []);

  return (
    <div className="app-wrapper">
      <div className="cyber-grid-overlay"></div>

      {/* Top Workspace Header */}
      <nav className="navbar" style={{ padding: '0.75rem 2rem' }}>
        <div className="nav-container">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
            <button onClick={onBackToLanding} className="workspace-back-btn">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M19 12H5M12 19l-7-7 7-7" />
              </svg>
              Landing Page
            </button>

            <div className="nav-brand" style={{ cursor: 'default' }}>
              <div className="brand-shield" style={{ width: '32px', height: '32px' }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <span className="brand-name" style={{ fontSize: '1.2rem' }}>ZEROTRACE SOC CONSOLE</span>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div className={`status-pill ${health.connected ? '' : 'disconnected'}`}>
              <span className="status-pulse-dot" style={{ backgroundColor: health.connected ? '#10b981' : '#f43f5e' }}></span>
              {health.connected ? `API v${health.version || '1.0.0'} (${health.latencyMs}ms)` : 'BACKEND OFFLINE'}
            </div>
          </div>
        </div>
      </nav>

      {/* Main Scroll-Based SOC Investigation Workspace */}
      <main className="workspace-wrapper">
        {/* SECTION 1: Incident Overview & Triage Queue */}
        <IncidentOverview
          selectedIncidentId={selectedIncidentId}
          onSelectIncident={(id) => setSelectedIncidentId(id)}
          selectedIncidentData={selectedIncidentData}
          setSelectedIncidentData={setSelectedIncidentData}
        />

        {/* SECTION 2: Attack Investigation & Chronological Timeline */}
        <AttackInvestigation
          selectedIncidentId={selectedIncidentId || selectedIncidentData?.incident?.id}
          selectedIncidentData={selectedIncidentData}
        />

        {/* SECTION 3: Threat Intelligence & MITRE Matrix */}
        <ThreatIntelligence
          selectedIncidentId={selectedIncidentId || selectedIncidentData?.incident?.id}
          selectedIncidentData={selectedIncidentData}
        />

        {/* SECTION 4: AI Investigation & Response Synthesis */}
        <AIInvestigationResponse
          selectedIncidentId={selectedIncidentId || selectedIncidentData?.incident?.id}
          selectedIncidentData={selectedIncidentData}
        />
      </main>
    </div>
  );
}
