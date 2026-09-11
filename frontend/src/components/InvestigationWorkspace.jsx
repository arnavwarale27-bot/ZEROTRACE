import React, { useState, useEffect } from 'react';
import { fetchHealthStatus, fetchIncidents, fetchIncidentById, fetchInvestigation } from '../services/api';
import AttackInvestigation from './AttackInvestigation';
import ThreatIntelligence from './ThreatIntelligence';
import AIInvestigationResponse from './AIInvestigationResponse';

export default function InvestigationWorkspace({ onBackToLanding }) {
  const [health, setHealth] = useState({ connected: false, loading: true });
  const [incidents, setIncidents] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncidentData, setSelectedIncidentData] = useState(null);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'timeline' | 'threat_intel' | 'ai_investigation'
  const [investigationData, setInvestigationData] = useState(null);

  // Check health & fetch incident list on mount
  useEffect(() => {
    const init = async () => {
      const h = await fetchHealthStatus();
      setHealth(h);

      try {
        setLoadingList(true);
        const list = await fetchIncidents();
        setIncidents(list || []);
        if (list && list.length > 0) {
          handleSelectIncident(list[0].id);
        }
      } catch (err) {
        console.error('Failed to load incidents:', err);
      } finally {
        setLoadingList(false);
      }
    };
    init();
  }, []);

  // Fetch full incident details when selection changes
  const handleSelectIncident = async (incidentId) => {
    if (!incidentId) return;
    setSelectedIncidentId(incidentId);
    try {
      const data = await fetchIncidentById(incidentId);
      setSelectedIncidentData(data);
      // Fetch AI investigation if exists for actions
      const inv = await fetchInvestigation(incidentId);
      setInvestigationData(inv);
    } catch (err) {
      console.error(`Failed to load incident ${incidentId}:`, err);
    }
  };

  const incident = selectedIncidentData?.incident;
  const events = selectedIncidentData?.events || [];
  const actions = investigationData?.recommended_actions || [];

  // Metrics calculations
  const confidenceScore = investigationData?.investigation?.confidence_score !== undefined
    ? Math.round(investigationData.investigation.confidence_score * 100)
    : 85;

  const severity = (incident?.severity || 'HIGH').toUpperCase();

  // Scroll to section helper for tab clicks
  const handleTabClick = (tabKey, sectionId) => {
    setActiveTab(tabKey);
    const elem = document.getElementById(sectionId);
    if (elem) {
      elem.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <div className="console-ambient-canvas">
      {/* Diffuse ambient blue glow layers */}
      <div className="ambient-glow-layer">
        <div className="ambient-glow-top-right"></div>
        <div className="ambient-glow-bottom-left"></div>
      </div>

      {/* Main Floating Tablet Frame */}
      <div className="floating-tablet-frame">
        {/* Tablet Top Navigation Bar */}
        <header className="tablet-navbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div className="brand-cube-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span className="brand-name" style={{ fontSize: '1.05rem', letterSpacing: '0.04em' }}>ZEROTRACE</span>
          </div>

          {/* Center Pill Tabs (Reference Style) */}
          <nav className="center-pill-tabs">
            <button
              onClick={() => handleTabClick('overview', 'overview-section')}
              className={`center-pill-btn ${activeTab === 'overview' ? 'active' : ''}`}
            >
              Overview
            </button>
            <button
              onClick={() => handleTabClick('timeline', 'timeline-section')}
              className={`center-pill-btn ${activeTab === 'timeline' ? 'active' : ''}`}
            >
              Timeline
            </button>
            <button
              onClick={() => handleTabClick('threat_intel', 'threat-intelligence-section')}
              className={`center-pill-btn ${activeTab === 'threat_intel' ? 'active' : ''}`}
            >
              Threat Intel
            </button>
            <button
              onClick={() => handleTabClick('ai_investigation', 'ai-investigation-section')}
              className={`center-pill-btn ${activeTab === 'ai_investigation' ? 'active' : ''}`}
            >
              AI Investigation
            </button>
          </nav>

          {/* Right Header Actions */}
          <div className="top-right-actions">
            <button onClick={onBackToLanding} className="workspace-back-btn">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M19 12H5M12 19l-7-7 7-7" />
              </svg>
              Landing
            </button>

            {/* Notification Bell with Badge */}
            <div className="nav-bell-btn" title="Live SOC Alerts">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              <span className="bell-badge-dot"></span>
            </div>

            {/* User Profile Pill */}
            <div className="user-profile-pill">
              <div className="user-avatar-circle">AR</div>
              <span style={{ fontWeight: 600, fontSize: '0.78rem' }}>Analyst</span>
            </div>

            {/* Backend Health Status */}
            <div className={`status-pill ${health.connected ? '' : 'disconnected'}`}>
              <span className="status-pulse-dot" style={{ backgroundColor: health.connected ? '#10b981' : '#f43f5e' }}></span>
              {health.connected ? `API v${health.version || '1.0.0'} (${health.latencyMs}ms)` : 'OFFLINE'}
            </div>
          </div>
        </header>

        {/* Tablet Two-Column Workspace Layout */}
        <div className="tablet-body-grid">
          {/* ========================================================================= */}
          {/* LEFT SIDEBAR (Tasks/Incidents, Recent Activity, Quick Access) */}
          {/* ========================================================================= */}
          <aside className="tablet-sidebar">
            {/* 1. Incidents Triage Card */}
            <div className="sidebar-panel-card">
              <div className="sidebar-panel-header">
                <div className="sidebar-panel-title">
                  <span>Incidents</span>
                  <span className="panel-count-badge">{incidents.length}</span>
                </div>
                <div className="sidebar-icon-actions">
                  <button
                    onClick={() => handleSelectIncident(selectedIncidentId)}
                    className="sidebar-icon-btn"
                    title="Refresh Incident Queue"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="23 4 23 10 17 10" />
                      <polyline points="1 20 1 14 7 14" />
                      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
                    </svg>
                  </button>
                </div>
              </div>

              {loadingList ? (
                <div style={{ textAlign: 'center', padding: '2rem 1rem', color: '#64748b', fontSize: '0.8rem' }}>
                  Loading incidents queue...
                </div>
              ) : (
                <div className="sidebar-incident-items-list">
                  {incidents.map((inc) => {
                    const isSelected = selectedIncidentId === inc.id;
                    const isCrit = (inc.severity || '').toUpperCase() === 'CRITICAL';
                    const isHigh = (inc.severity || '').toUpperCase() === 'HIGH';

                    return (
                      <div
                        key={inc.id}
                        onClick={() => handleSelectIncident(inc.id)}
                        className={`sidebar-incident-item ${isSelected ? 'active' : ''}`}
                      >
                        {/* Checkbox indicator matching reference image */}
                        <div className="item-check-indicator">
                          {isSelected && (
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                              <polyline points="20 6 9 17 4 12" />
                            </svg>
                          )}
                        </div>

                        <div className="item-title-col">
                          <div className="item-title-text" title={inc.title || inc.id}>
                            {inc.title ? inc.title.split(':')[0] : inc.id}
                          </div>
                          <div className="item-sub-text">
                            {inc.id} • {inc.event_ids ? `${inc.event_ids.length} evts` : '1 evt'}
                          </div>
                        </div>

                        {/* Notification alert dot / badge pill */}
                        {isCrit ? (
                          <div className="item-badge-pill critical" title="Critical Severity">1</div>
                        ) : isHigh ? (
                          <div className="item-badge-pill high" title="High Severity">!</div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* 2. Recent Activity Card */}
            <div className="sidebar-panel-card">
              <div className="sidebar-panel-header">
                <div className="sidebar-panel-title">
                  <span>Recent Activity</span>
                </div>
              </div>

              <div className="recent-activity-list">
                <div className="recent-activity-item">
                  <div className="activity-icon-box">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                  </div>
                  <div className="activity-content">
                    <div className="activity-title">Telemetry Correlated</div>
                    <div className="activity-time">37 minutes ago</div>
                  </div>
                </div>

                <div className="recent-activity-item">
                  <div className="activity-icon-box" style={{ color: '#c084fc' }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                    </svg>
                  </div>
                  <div className="activity-content">
                    <div className="activity-title">MITRE Persistence Flagged</div>
                    <div className="activity-time">42 minutes ago</div>
                  </div>
                </div>
              </div>
            </div>

            {/* 3. Quick Access Card (3 Glass Squircles) */}
            <div className="sidebar-panel-card">
              <div className="sidebar-panel-header">
                <div className="sidebar-panel-title">
                  <span>Quick Access</span>
                </div>
              </div>

              <div className="quick-access-grid">
                <div
                  className="squircle-btn"
                  onClick={() => handleTabClick('timeline', 'timeline-section')}
                  title="Go to Attack Timeline"
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                    <line x1="16" y1="2" x2="16" y2="6" />
                    <line x1="8" y1="2" x2="8" y2="6" />
                    <line x1="3" y1="10" x2="21" y2="10" />
                  </svg>
                  <span className="squircle-lbl">Timeline</span>
                </div>

                <div
                  className="squircle-btn"
                  onClick={() => handleTabClick('threat_intel', 'threat-intelligence-section')}
                  title="Inspect Extracted IOCs"
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                  </svg>
                  <span className="squircle-lbl">IOCs</span>
                </div>

                <div
                  className="squircle-btn"
                  onClick={() => handleTabClick('ai_investigation', 'ai-investigation-section')}
                  title="Trigger AI Investigation"
                >
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
                  </svg>
                  <span className="squircle-lbl">AI Agent</span>
                </div>
              </div>
            </div>
          </aside>

          {/* ========================================================================= */}
          {/* MAIN CONTENT WORKSPACE */}
          {/* ========================================================================= */}
          <main className="tablet-main-content">
            {/* Header Title Row */}
            <div className="main-content-header" id="overview-section">
              <div>
                <h1 className="main-content-title">Incident Overview</h1>
                <div style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                  {incident?.title || 'Selected Security Incident Triage & Attack Chain'}
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span className="inv-id-tag">{selectedIncidentId || 'No Selection'}</span>
                <button
                  onClick={() => handleSelectIncident(selectedIncidentId)}
                  className="new-triage-btn"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                  Re-correlate
                </button>
              </div>
            </div>

            {/* Top 3 Sleek Metric Cards (Exact Reference Design) */}
            <div className="metric-cards-row">
              {/* Metric Card 1: Active Events with Sine Wave Curve */}
              <div className="sleek-metric-card">
                <div className="card-top-row">
                  <span className="metric-card-lbl">Active Telemetry Events</span>
                  <span className="card-dots-menu">•••</span>
                </div>

                <div className="metric-card-val">
                  {events.length > 0 ? events.length : (incident?.event_ids?.length || 12)}
                </div>

                {/* SVG Smooth Sine Wave Curve with gradient fill */}
                <div className="wave-curve-container">
                  <svg viewBox="0 0 240 55" className="wave-curve-svg" preserveAspectRatio="none">
                    <defs>
                      <linearGradient id="waveGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.45" />
                        <stop offset="100%" stopColor="#1d4ed8" stopOpacity="0.0" />
                      </linearGradient>
                    </defs>
                    <path
                      d="M 0,40 Q 30,50 60,32 T 120,38 T 180,18 T 240,10 L 240,55 L 0,55 Z"
                      fill="url(#waveGrad)"
                    />
                    <path
                      d="M 0,40 Q 30,50 60,32 T 120,38 T 180,18 T 240,10"
                      fill="none"
                      stroke="#60a5fa"
                      strokeWidth="2.5"
                    />
                  </svg>
                  <div className="wave-axis-labels">
                    <span>Jan</span>
                    <span>Feb</span>
                    <span>Mar</span>
                    <span>Apr</span>
                    <span>Sep</span>
                    <span>Dec</span>
                  </div>
                </div>
              </div>

              {/* Metric Card 2: Severity & Scope with Vertical Rounded Pill Bars */}
              <div className="sleek-metric-card">
                <div className="card-top-row">
                  <span className="metric-card-lbl">Severity & Blast Radius</span>
                  <span className="card-dots-menu">•••</span>
                </div>

                <div className="metric-card-val" style={{ color: severity === 'CRITICAL' ? '#f43f5e' : '#fbbf24' }}>
                  {severity}
                </div>

                {/* Vertical Rounded Pill Bar Chart */}
                <div className="pill-bars-container">
                  <div className="pill-bar" style={{ height: '35%' }}></div>
                  <div className="pill-bar" style={{ height: '65%' }}></div>
                  <div className="pill-bar" style={{ height: '45%' }}></div>
                  <div className="pill-bar active" style={{ height: '90%' }}></div>
                  <div className="pill-bar" style={{ height: '55%' }}></div>
                  <div className="pill-bar" style={{ height: '75%' }}></div>
                </div>
                <div className="wave-axis-labels">
                  <span>Sysmon</span>
                  <span>EDR</span>
                  <span>Net</span>
                  <span>DNS</span>
                  <span>Auth</span>
                  <span>Audit</span>
                </div>
              </div>

              {/* Metric Card 3: AI Grounded Confidence with Circular Radial Ring */}
              <div className="sleek-metric-card">
                <div className="card-top-row">
                  <span className="metric-card-lbl">AI Grounded Confidence</span>
                  <span className="card-dots-menu">•••</span>
                </div>

                <div className="metric-card-val">
                  {confidenceScore}%
                </div>

                {/* Radial Progress Ring */}
                <div className="radial-progress-container">
                  <svg viewBox="0 0 80 80" className="radial-gauge-svg">
                    <circle
                      cx="40"
                      cy="40"
                      r="32"
                      stroke="rgba(255,255,255,0.08)"
                      strokeWidth="6"
                      fill="none"
                    />
                    <circle
                      cx="40"
                      cy="40"
                      r="32"
                      stroke="#60a5fa"
                      strokeWidth="6"
                      strokeDasharray="201"
                      strokeDashoffset={201 - (201 * confidenceScore) / 100}
                      strokeLinecap="round"
                      fill="none"
                      transform="rotate(-90 40 40)"
                    />
                    <text
                      x="40"
                      y="45"
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize="14"
                      fontWeight="800"
                      fontFamily="sans-serif"
                    >
                      {confidenceScore}%
                    </text>
                  </svg>
                </div>
              </div>
            </div>

            {/* Middle Card: Attack Progression & Milestones (Reference Design Centerpiece) */}
            <div className="attack-milestones-card" id="timeline-section">
              <div className="milestones-header-row">
                <h3 className="milestones-title">Attack Milestones & Progression</h3>
                <div className="timeline-dropdown-pill">
                  <span>Timeline</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </div>
              </div>

              <div className="phase-progress-info">
                <div className="phase-title-text">
                  {incident?.title ? incident.title.split(':')[0] : 'Kill Chain Progression'} — Phase 3
                </div>
                <div className="phase-percent-text">75% Verified</div>
              </div>

              {/* Horizontal Stepped Progress Bar */}
              <div className="stepped-track-wrapper">
                <div className="stepped-track">
                  <div className="stepped-track-fill" style={{ width: '75%' }}></div>
                </div>
                <div className="stepped-nodes-labels">
                  <span>Initial Access</span>
                  <span>Execution</span>
                  <span>Persistence</span>
                  <span>C2 Egress</span>
                </div>
              </div>

              {/* Area Curve Velocity Spline Chart */}
              <div className="timeline-velocity-chart">
                <svg viewBox="0 0 500 130" className="wave-curve-svg" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35" />
                      <stop offset="100%" stopColor="#1e3a8a" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>
                  <path
                    d="M 0,110 Q 50,40 120,70 T 250,55 T 380,30 T 500,10 L 500,130 L 0,130 Z"
                    fill="url(#areaGrad)"
                  />
                  <path
                    d="M 0,110 Q 50,40 120,70 T 250,55 T 380,30 T 500,10"
                    fill="none"
                    stroke="#93c5fd"
                    strokeWidth="3"
                  />
                </svg>
              </div>

              {/* Chronological Timeline Stream Component */}
              <AttackInvestigation
                selectedIncidentId={selectedIncidentId}
                selectedIncidentData={selectedIncidentData}
              />
            </div>

            {/* SECTION 3: Threat Intelligence & MITRE Matrix */}
            <ThreatIntelligence
              selectedIncidentId={selectedIncidentId}
              selectedIncidentData={selectedIncidentData}
            />

            {/* SECTION 4: AI Investigation & Response Synthesis */}
            <AIInvestigationResponse
              selectedIncidentId={selectedIncidentId}
              selectedIncidentData={selectedIncidentData}
            />
          </main>
        </div>
      </div>

      {/* Floating Pending Response Actions Card (Matches Reference Image Bottom-Right Float) */}
      {actions && actions.length > 0 && (
        <aside className="floating-pending-actions-card">
          <div className="floating-card-header">
            <h4 className="floating-card-title">Pending Actions</h4>
            <span className="card-dots-menu">•••</span>
          </div>

          <div className="pending-actions-list-mini">
            {actions.slice(0, 3).map((act) => (
              <div key={act.id} className="pending-action-item-mini">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem', maxWidth: '240px' }}>
                  <span style={{ fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {act.description}
                  </span>
                  <span style={{ fontSize: '0.68rem', color: '#94a3b8' }}>{act.action_type}</span>
                </div>
                <div className="mini-check-pill">
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </div>
              </div>
            ))}
          </div>

          <div style={{ fontSize: '0.68rem', color: '#64748b', textAlign: 'center', paddingTop: '0.2rem' }}>
            Requires SOC Analyst dual-token approval
          </div>
        </aside>
      )}
    </div>
  );
}
