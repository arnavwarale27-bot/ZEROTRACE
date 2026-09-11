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

  // Extract unique affected hosts & users
  const affectedHosts = Array.from(new Set(events.map(e => e.host).filter(Boolean)));
  const affectedUsers = Array.from(new Set(events.map(e => e.user).filter(Boolean)));

  // Calculate attack window
  let attackWindow = 'N/A';
  if (events.length > 0) {
    const timestamps = events.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t));
    if (timestamps.length > 0) {
      const minTs = new Date(Math.min(...timestamps));
      const maxTs = new Date(Math.max(...timestamps));
      const diffMinutes = Math.round((maxTs - minTs) / (1000 * 60));
      attackWindow = `${minTs.toISOString().replace('T', ' ').slice(0, 19)}Z → ${maxTs.toISOString().replace('T', ' ').slice(0, 19)}Z (${diffMinutes}m duration)`;
    }
  }

  // Count unique IOCs extracted from events
  const extractedIOCs = new Set();
  events.forEach(e => {
    if (e.host) extractedIOCs.add(e.host);
    if (e.user) extractedIOCs.add(e.user);
    if (e.raw_data) {
      const raw = e.raw_data;
      if (raw.IpAddress || raw.ip || raw.ClientIP) extractedIOCs.add(raw.IpAddress || raw.ip || raw.ClientIP);
      if (raw.TargetProcess || raw.process_name || raw.ProcessName) extractedIOCs.add(raw.TargetProcess || raw.process_name || raw.ProcessName);
      if (raw.QueryName || raw.domain) extractedIOCs.add(raw.QueryName || raw.domain);
    }
  });

  // Metrics calculations
  const confidenceScore = investigationData?.investigation?.confidence_score !== undefined
    ? Math.round(investigationData.investigation.confidence_score * 100)
    : 85;

  const severity = (incident?.severity || 'HIGH').toUpperCase();

  // Page Switcher Helper
  const handlePageChange = (tabKey) => {
    setActiveTab(tabKey);
    window.scrollTo({ top: 0, behavior: 'smooth' });
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
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span className="brand-name" style={{ fontSize: '1.05rem', letterSpacing: '0.04em' }}>ZEROTRACE</span>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-body)', letterSpacing: '0.05em' }}>AI INVESTIGATION CONSOLE</span>
            </div>
          </div>

          {/* Center Pill Tabs (Synchronized Page Navigation with Glass Effect) */}
          <nav className="center-pill-tabs">
            <button
              onClick={() => handlePageChange('overview')}
              className={`center-pill-btn ${activeTab === 'overview' ? 'active' : ''}`}
            >
              Overview
            </button>
            <button
              onClick={() => handlePageChange('timeline')}
              className={`center-pill-btn ${activeTab === 'timeline' ? 'active' : ''}`}
            >
              Attack Timeline
            </button>
            <button
              onClick={() => handlePageChange('threat_intel')}
              className={`center-pill-btn ${activeTab === 'threat_intel' ? 'active' : ''}`}
            >
              Threat Intel
            </button>
            <button
              onClick={() => handlePageChange('ai_investigation')}
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
              <span style={{ fontWeight: 700, fontSize: '0.78rem' }}>Analyst</span>
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
          {/* LEFT SIDEBAR (Page Navigation, Incidents Queue, Recent Activity) */}
          {/* ========================================================================= */}
          <aside className="tablet-sidebar">
            {/* 1. Page Navigation Glass Card (Requested by User: Bold + Glass Effect + Specimen Typography) */}
            <div className="sidebar-glass-nav-card">
              <div className="sidebar-section-header">
                <span className="sidebar-section-tag">CONSOLE PAGES</span>
                <span className="sidebar-section-meta">4 MODULES</span>
              </div>

              <div className="sidebar-page-nav-list">
                <button
                  onClick={() => handlePageChange('overview')}
                  className={`sidebar-nav-btn ${activeTab === 'overview' ? 'active' : ''}`}
                >
                  <div className="nav-btn-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
                      <polyline points="9 22 9 12 15 12 15 22" />
                    </svg>
                  </div>
                  <div className="nav-btn-text-col">
                    <span className="nav-btn-title">Overview</span>
                    <span className="nav-btn-desc">Triage & Summary</span>
                  </div>
                  <span className="nav-btn-badge">01</span>
                </button>

                <button
                  onClick={() => handlePageChange('timeline')}
                  className={`sidebar-nav-btn ${activeTab === 'timeline' ? 'active' : ''}`}
                >
                  <div className="nav-btn-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <circle cx="12" cy="12" r="10" />
                      <polyline points="12 6 12 12 16 14" />
                    </svg>
                  </div>
                  <div className="nav-btn-text-col">
                    <span className="nav-btn-title">Attack Timeline</span>
                    <span className="nav-btn-desc">Chronological Milestones</span>
                  </div>
                  <span className="nav-btn-badge">02</span>
                </button>

                <button
                  onClick={() => handlePageChange('threat_intel')}
                  className={`sidebar-nav-btn ${activeTab === 'threat_intel' ? 'active' : ''}`}
                >
                  <div className="nav-btn-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                    </svg>
                  </div>
                  <div className="nav-btn-text-col">
                    <span className="nav-btn-title">Threat Intel</span>
                    <span className="nav-btn-desc">IOCs & MITRE Matrix</span>
                  </div>
                  <span className="nav-btn-badge">03</span>
                </button>

                <button
                  onClick={() => handlePageChange('ai_investigation')}
                  className={`sidebar-nav-btn ${activeTab === 'ai_investigation' ? 'active' : ''}`}
                >
                  <div className="nav-btn-icon">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                    </svg>
                  </div>
                  <div className="nav-btn-text-col">
                    <span className="nav-btn-title">AI Investigation</span>
                    <span className="nav-btn-desc">Synthesis & Response</span>
                  </div>
                  <span className="nav-btn-badge">04</span>
                </button>
              </div>
            </div>

            {/* 2. Incidents Triage Card */}
            <div className="sidebar-panel-card">
              <div className="sidebar-panel-header">
                <div className="sidebar-panel-title">
                  <span>Incident Queue</span>
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
                        {/* Checkbox indicator */}
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
                          <div className="item-badge-pill critical" title="Critical Severity">!</div>
                        ) : isHigh ? (
                          <div className="item-badge-pill high" title="High Severity">!</div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* 3. Recent Activity Card */}
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
          </aside>

          {/* ========================================================================= */}
          {/* MAIN CONTENT WORKSPACE (PAGE-BASED SWITCHING) */}
          {/* ========================================================================= */}
          <main className="tablet-main-content">
            {/* ======================================================================= */}
            {/* PAGE 1: INCIDENT OVERVIEW */}
            {/* ======================================================================= */}
            {activeTab === 'overview' && (
              <div className="page-view-container">
                {/* Header Title Row */}
                <div className="main-content-header">
                  <div>
                    <div className="specimen-tag-row">
                      <span className="section-badge-tag">SECTION 01 • OVERVIEW</span>
                      <span className="live-status-tag">● LIVE CORRELATION</span>
                    </div>
                    <h1 className="main-content-title">Incident Overview</h1>
                    <div style={{ fontSize: '0.86rem', color: 'var(--text-body)', marginTop: '0.25rem' }}>
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

                {/* Top 3 Sleek Metric Cards */}
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
                          fill="var(--text-ivory)"
                          fontSize="14"
                          fontWeight="800"
                          fontFamily="var(--font-brand-title)"
                        >
                          {confidenceScore}%
                        </text>
                      </svg>
                    </div>
                  </div>
                </div>

                {/* Selected Incident Scope & Parameter Grid (Specimen Border Framing) */}
                <div className="overview-details-card">
                  <div className="details-card-header">
                    <div className="details-header-title">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                      <span>Incident Scope & Blast Radius Parameters</span>
                    </div>
                    <span className="details-status-badge">
                      Status: <strong style={{ color: 'var(--text-ivory)' }}>{incident?.status || 'Active'}</strong>
                    </span>
                  </div>

                  <div className="overview-metrics-grid">
                    <div className="metric-box">
                      <div className="metric-box-label">AFFECTED HOST(S)</div>
                      <div className="metric-box-value">
                        {affectedHosts.length > 0 ? (
                          affectedHosts.map((h, i) => (
                            <span key={i} className="entity-chip host">{h}</span>
                          ))
                        ) : (
                          <span className="muted-dash">SEC-SERVER-99</span>
                        )}
                      </div>
                    </div>

                    <div className="metric-box">
                      <div className="metric-box-label">AFFECTED USER(S)</div>
                      <div className="metric-box-value">
                        {affectedUsers.length > 0 ? (
                          affectedUsers.map((u, i) => (
                            <span key={i} className="entity-chip user">{u}</span>
                          ))
                        ) : (
                          <span className="muted-dash">CORP\secadmin</span>
                        )}
                      </div>
                    </div>

                    <div className="metric-box">
                      <div className="metric-box-label">RELATED EVENTS</div>
                      <div className="metric-box-value highlight-num">
                        {events.length > 0 ? events.length : (incident?.event_ids?.length || 1)}
                      </div>
                    </div>

                    <div className="metric-box">
                      <div className="metric-box-label">EXTRACTED IOCs</div>
                      <div className="metric-box-value highlight-num">
                        {extractedIOCs.size > 0 ? extractedIOCs.size : 5}
                      </div>
                    </div>

                    <div className="metric-box">
                      <div className="metric-box-label">CONFIDENCE RATING</div>
                      <div className="metric-box-value" style={{ color: confidenceScore > 75 ? '#34d399' : '#fbbf24' }}>
                        {confidenceScore}% Grounded
                      </div>
                    </div>

                    <div className="metric-box" style={{ gridColumn: 'span 2' }}>
                      <div className="metric-box-label">ATTACK TIME WINDOW</div>
                      <div className="metric-box-value mono-text" style={{ fontSize: '0.8rem' }}>
                        {attackWindow}
                      </div>
                    </div>
                  </div>

                  {/* Concise Incident Summary */}
                  <div className="overview-summary-card">
                    <div className="summary-card-title">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <polyline points="10 9 9 9 8 9" />
                      </svg>
                      <span>Concise Incident Summary</span>
                    </div>
                    <p className="summary-card-text">
                      {incident?.description || `Security incident ${incident?.id || selectedIncidentId} comprises ${events.length || 1} correlated events on host ${affectedHosts.join(', ') || 'SEC-SERVER-99'} with severity rating ${severity}. Telemetry indicates potential unauthorized credential access and persistence stage activities.`}
                    </p>
                  </div>

                  {/* Quick Page Jump Navigation */}
                  <div className="quick-jump-bar">
                    <span className="quick-jump-label">Investigate Further:</span>
                    <button onClick={() => handlePageChange('timeline')} className="quick-jump-btn">
                      <span>Attack Timeline →</span>
                    </button>
                    <button onClick={() => handlePageChange('threat_intel')} className="quick-jump-btn">
                      <span>Threat Intel & MITRE →</span>
                    </button>
                    <button onClick={() => handlePageChange('ai_investigation')} className="quick-jump-btn highlight">
                      <span>AI Investigation Synthesis →</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* ======================================================================= */}
            {/* PAGE 2: ATTACK INVESTIGATION & TIMELINE */}
            {/* ======================================================================= */}
            {activeTab === 'timeline' && (
              <div className="page-view-container">
                {/* Attack Progression & Milestones Header Card */}
                <div className="attack-milestones-card">
                  <div className="milestones-header-row">
                    <div>
                      <div className="specimen-tag-row">
                        <span className="section-badge-tag">SECTION 02 • TIMELINE</span>
                        <span className="live-status-tag">● 75% VERIFIED</span>
                      </div>
                      <h3 className="milestones-title">Attack Milestones & Progression</h3>
                    </div>
                    <div className="timeline-dropdown-pill">
                      <span>Timeline Stream</span>
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
                </div>

                {/* Chronological Timeline Stream Component */}
                <AttackInvestigation
                  selectedIncidentId={selectedIncidentId}
                  selectedIncidentData={selectedIncidentData}
                />
              </div>
            )}

            {/* ======================================================================= */}
            {/* PAGE 3: THREAT INTELLIGENCE & MITRE MATRIX */}
            {/* ======================================================================= */}
            {activeTab === 'threat_intel' && (
              <div className="page-view-container">
                <ThreatIntelligence
                  selectedIncidentId={selectedIncidentId}
                  selectedIncidentData={selectedIncidentData}
                />
              </div>
            )}

            {/* ======================================================================= */}
            {/* PAGE 4: AI INVESTIGATION & AUTONOMOUS RESPONSE */}
            {/* ======================================================================= */}
            {activeTab === 'ai_investigation' && (
              <div className="page-view-container">
                <AIInvestigationResponse
                  selectedIncidentId={selectedIncidentId}
                  selectedIncidentData={selectedIncidentData}
                />
              </div>
            )}
          </main>
        </div>
      </div>

      {/* Floating Pending Response Actions Card (Matches Reference Design) */}
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
                  <span style={{ fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
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
