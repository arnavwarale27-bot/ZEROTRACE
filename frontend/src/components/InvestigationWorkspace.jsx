import React, { useState, useEffect } from 'react';
import { 
  fetchHealthStatus, 
  fetchIncidents, 
  fetchIncidentById, 
  fetchInvestigation,
  triggerCorrelation 
} from '../services/api';
import AttackInvestigation from './AttackInvestigation';
import ThreatIntelligence from './ThreatIntelligence';
import AIInvestigationResponse from './AIInvestigationResponse';
import LogIncidentModal from './LogIncidentModal';

export default function InvestigationWorkspace({ onBackToLanding }) {
  const [health, setHealth] = useState({ connected: false, loading: true });
  const [incidents, setIncidents] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncidentData, setSelectedIncidentData] = useState(null);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'timeline' | 'threat_intel' | 'ai_investigation'
  const [investigationData, setInvestigationData] = useState(null);

  // Interactive UI states for demo & judges
  const [isLogModalOpen, setIsLogModalOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);
  const [isAlertsOpen, setIsAlertsOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [refreshingList, setRefreshingList] = useState(false);
  const [timelineOrder, setTimelineOrder] = useState('asc'); // 'asc' | 'desc'
  const [approvedActionIds, setApprovedActionIds] = useState({});

  // Toast notification helper
  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4500);
  };

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
      // Fetch AI investigation if exists
      const inv = await fetchInvestigation(incidentId);
      setInvestigationData(inv);
    } catch (err) {
      console.error(`Failed to load incident ${incidentId}:`, err);
    }
  };

  // Manual refresh of incident queue
  const handleRefreshQueue = async () => {
    setRefreshingList(true);
    try {
      const list = await fetchIncidents();
      setIncidents(list || []);
      showToast(`Incident queue updated (${list.length} incidents)`);
    } catch (err) {
      showToast(`Queue refresh failed: ${err.message}`);
    } finally {
      setTimeout(() => setRefreshingList(false), 500);
    }
  };

  // Re-run correlation engine across all events
  const handleTriggerReCorrelation = async () => {
    setCorrelating(true);
    try {
      const res = await triggerCorrelation(1440, 1);
      const list = await fetchIncidents();
      setIncidents(list || []);
      if (selectedIncidentId) {
        await handleSelectIncident(selectedIncidentId);
      }
      showToast(`Correlation executed! Processed ${res.events_processed} events into ${res.incidents_created} incidents.`);
    } catch (err) {
      console.error('Correlation error:', err);
      showToast(`Correlation failed: ${err.message}`);
    } finally {
      setCorrelating(false);
    }
  };

  // Incident created via modal callback
  const handleIncidentCreated = async (newIncidentId, message) => {
    try {
      const list = await fetchIncidents();
      setIncidents(list || []);
      if (newIncidentId) {
        await handleSelectIncident(newIncidentId);
      }
      showToast(message || `Incident ${newIncidentId} created & correlated live!`);
    } catch (err) {
      console.error('Failed to refresh after incident creation:', err);
    }
  };

  // Toggle approval state for response actions
  const toggleActionApproval = (actionId) => {
    setApprovedActionIds(prev => {
      const nextState = !prev[actionId];
      if (nextState) {
        showToast(`Remediation action approved! Dual-token authorization signed.`);
      }
      return { ...prev, [actionId]: nextState };
    });
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

  // =========================================================================
  // DYNAMIC KILL CHAIN PROGRESSION (Calculated from real incident telemetry)
  // =========================================================================
  const calculateProgression = () => {
    if (!events || events.length === 0) {
      return { 
        phase: 1, 
        percent: 25, 
        label: 'Phase 1 — Initial Reconnaissance',
        stagesList: ['Initial Access'] 
      };
    }

    let highestRank = 1;
    const detectedStages = new Set();

    events.forEach(e => {
      const stage = (e.attack_stage || '').toLowerCase();
      const type = (e.event_type || '').toLowerCase();
      const raw = JSON.stringify(e.raw_data || {}).toLowerCase();

      if (
        stage.includes('command') || stage.includes('c2') || stage.includes('exfil') || stage.includes('impact') ||
        type.includes('c2') || type.includes('exfil') || raw.includes('c2-exfil') || raw.includes(':4444')
      ) {
        highestRank = Math.max(highestRank, 4);
        detectedStages.add('C2 Egress');
      } else if (
        stage.includes('persistence') || stage.includes('credential') || stage.includes('privilege') || stage.includes('defense') ||
        type.includes('persistence') || type.includes('credential') || type.includes('lsass') || 
        raw.includes('mimikatz') || raw.includes('procdump') || raw.includes('backdoorkey')
      ) {
        highestRank = Math.max(highestRank, 3);
        detectedStages.add('Persistence');
      } else if (
        stage.includes('execution') || type.includes('process') || type.includes('powershell') || 
        type.includes('script') || raw.includes('powershell')
      ) {
        highestRank = Math.max(highestRank, 2);
        detectedStages.add('Execution');
      } else {
        highestRank = Math.max(highestRank, 1);
        detectedStages.add('Initial Access');
      }
    });

    const percentMap = { 1: 25, 2: 50, 3: 75, 4: 100 };
    const labelMap = {
      1: 'Phase 1 — Initial Access & Recon',
      2: 'Phase 2 — Execution & Discovery',
      3: 'Phase 3 — Persistence & Credential Theft',
      4: 'Phase 4 — C2 Beaconing & Data Exfiltration',
    };

    return {
      phase: highestRank,
      percent: percentMap[highestRank] || 25,
      label: labelMap[highestRank] || 'Phase 1 — Initial Access',
      stagesList: Array.from(detectedStages),
    };
  };

  const progression = calculateProgression();

  // Page Switcher Helper
  const handlePageChange = (tabKey) => {
    setActiveTab(tabKey);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="console-ambient-canvas">
      {/* Toast Notification Banner */}
      {toastMessage && (
        <div className="console-toast-banner">
          <div className="toast-icon">⚡</div>
          <div className="toast-text">{toastMessage}</div>
          <button onClick={() => setToastMessage(null)} className="toast-close">✕</button>
        </div>
      )}

      {/* Diffuse ambient blue glow layers */}
      <div className="ambient-glow-layer">
        <div className="ambient-glow-top-right"></div>
        <div className="ambient-glow-bottom-left"></div>
      </div>

      {/* Log Incident Modal for Judges */}
      <LogIncidentModal
        isOpen={isLogModalOpen}
        onClose={() => setIsLogModalOpen(false)}
        onIncidentCreated={handleIncidentCreated}
      />

      {/* Main Floating Tablet Frame */}
      <div className="floating-tablet-frame">
        {/* Tablet Top Navigation Bar (Page pills removed as requested, leaving header clean) */}
        <header className="tablet-navbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div className="brand-cube-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span className="brand-name" style={{ fontSize: '1.05rem', letterSpacing: '0.04em' }}>ZEROTRACE</span>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-body)', letterSpacing: '0.05em' }}>AI SECURITY INVESTIGATION CONSOLE</span>
            </div>
          </div>

          {/* Right Header Actions */}
          <div className="top-right-actions">
            {/* Log New Incident Button for Judges */}
            <button 
              onClick={() => setIsLogModalOpen(true)} 
              className="header-log-incident-btn"
              title="Log new security incident or simulate attack for judges"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.8">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
              <span>Log Incident</span>
            </button>

            {/* Back to Landing Button */}
            <button onClick={onBackToLanding} className="workspace-back-btn">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M19 12H5M12 19l-7-7 7-7" />
              </svg>
              Landing
            </button>

            {/* Notification Bell with Dropdown Drawer */}
            <div style={{ position: 'relative' }}>
              <button 
                onClick={() => setIsAlertsOpen(!isAlertsOpen)} 
                className={`nav-bell-btn ${isAlertsOpen ? 'active' : ''}`} 
                title="Live SOC Alerts"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                  <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                </svg>
                <span className="bell-badge-dot"></span>
              </button>

              {/* Alerts Dropdown Drawer */}
              {isAlertsOpen && (
                <div className="alerts-dropdown-drawer">
                  <div className="drawer-header">
                    <span className="drawer-title">Live SOC Telemetry Stream</span>
                    <span className="drawer-count">{incidents.length} active</span>
                  </div>
                  <div className="drawer-items-list">
                    <div className="drawer-item critical">
                      <div className="drawer-item-title">CRITICAL: Credential Access Detected</div>
                      <div className="drawer-item-meta">Host: DC01.corp.internal • LSASS Dump</div>
                    </div>
                    <div className="drawer-item high">
                      <div className="drawer-item-title">HIGH: Encoded PowerShell Cradle</div>
                      <div className="drawer-item-meta">Host: FINANCE-PC04 • C2 Beaconing</div>
                    </div>
                    <div className="drawer-item info">
                      <div className="drawer-item-title">Correlation Engine Active</div>
                      <div className="drawer-item-meta">Automated rule clustering enabled</div>
                    </div>
                  </div>
                  <button 
                    onClick={() => { setIsAlertsOpen(false); showToast('All notifications marked as reviewed.'); }}
                    className="drawer-action-btn"
                  >
                    Mark All Reviewed
                  </button>
                </div>
              )}
            </div>

            {/* User Profile Pill with Popover */}
            <div style={{ position: 'relative' }}>
              <div 
                onClick={() => setIsProfileOpen(!isProfileOpen)} 
                className="user-profile-pill" 
                style={{ cursor: 'pointer' }}
                title="SOC Analyst Session & Authority Level"
              >
                <div className="user-avatar-circle">AR</div>
                <span style={{ fontWeight: 700, fontSize: '0.78rem' }}>Analyst</span>
              </div>

              {isProfileOpen && (
                <div className="profile-popover">
                  <div className="popover-title">Arnav Warale</div>
                  <div className="popover-badge">SOC Level 2 Investigator</div>
                  <div className="popover-info">Authority: Dual-Token Containment</div>
                  <div className="popover-info">Terminal: SOC-ALPHA-01</div>
                  <button 
                    onClick={() => { setIsProfileOpen(false); showToast('Session locked to workstation.'); }}
                    className="popover-btn"
                  >
                    Lock Console Session
                  </button>
                </div>
              )}
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
            {/* 1. Page Navigation Glass Card (EXCLUSIVELY HERE on Sidebar) */}
            <div className="sidebar-glass-nav-card">
              

              <div className="sidebar-page-nav-list">
                <button onClick={() => handlePageChange('overview')} className={`sidebar-nav-btn ${activeTab === 'overview' ? 'active' : ''}`}> <span className="nav-btn-title">Overview</span> </button>

                <button onClick={() => handlePageChange('timeline')} className={`sidebar-nav-btn ${activeTab === 'timeline' ? 'active' : ''}`}> <span className="nav-btn-title">Attack Timeline</span> </button>

                <button onClick={() => handlePageChange('threat_intel')} className={`sidebar-nav-btn ${activeTab === 'threat_intel' ? 'active' : ''}`}> <span className="nav-btn-title">Threat Intel</span> </button>

                <button onClick={() => handlePageChange('ai_investigation')} className={`sidebar-nav-btn ${activeTab === 'ai_investigation' ? 'active' : ''}`}> <span className="nav-btn-title">AI Investigation</span> </button>
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
                    onClick={handleRefreshQueue}
                    className={`sidebar-icon-btn ${refreshingList ? 'spinning' : ''}`}
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

              {/* Log New Incident Demo Button right inside the sidebar */}
              <button 
                onClick={() => setIsLogModalOpen(true)}
                className="sidebar-log-incident-btn"
              >
                <span className="plus-sym">+</span>
                <span>Log New Incident (Judge Demo)</span>
              </button>

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
                    <div className="activity-time">Just now</div>
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
                    <div className="activity-time">12 minutes ago</div>
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
                      onClick={handleTriggerReCorrelation}
                      disabled={correlating}
                      className="new-triage-btn"
                      title="Execute correlation engine across all unclustered events"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <polyline points="23 4 23 10 17 10" />
                        <polyline points="1 20 1 14 7 14" />
                        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
                      </svg>
                      {correlating ? 'Correlating...' : 'Re-correlate'}
                    </button>
                  </div>
                </div>

                {/* Top 3 Sleek Metric Cards */}
                <div className="metric-cards-row">
                  {/* Metric Card 1: Active Events with Sine Wave Curve */}
                  <div className="sleek-metric-card">
                    <div className="card-top-row">
                      <span className="metric-card-lbl">Active Telemetry Events</span>
                      <span className="card-dots-menu" title="Telemetry Source: Sysmon & EDR">•••</span>
                    </div>

                    <div className="metric-card-val">
                      {events.length > 0 ? events.length : (incident?.event_ids?.length || 1)}
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
                      <span className="card-dots-menu" title="Calculated from event types & attack stages">•••</span>
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
                      <span className="card-dots-menu" title="Evidence grounded correlation score">•••</span>
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

                {/* Selected Incident Scope & Parameter Grid */}
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
                          <span className="muted-dash">None specified</span>
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
                          <span className="muted-dash">None specified</span>
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
                        {extractedIOCs.size > 0 ? extractedIOCs.size : (events.length > 0 ? 2 : 0)}
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
                      {incident?.description || `Security incident ${incident?.id || selectedIncidentId} comprises ${events.length || 1} correlated events on host ${affectedHosts.join(', ') || 'Target Asset'} with severity rating ${severity}. Telemetry indicates potential unauthorized access and execution activities.`}
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
                {/* Attack Progression & Milestones Header Card (DYNAMIC Kill Chain) */}
                <div className="attack-milestones-card">
                  <div className="milestones-header-row">
                    <div>
                      <div className="specimen-tag-row">
                        <span className="section-badge-tag">SECTION 02 • TIMELINE</span>
                        <span className="live-status-tag">● {progression.percent}% KILL CHAIN PROGRESSION</span>
                      </div>
                      <h3 className="milestones-title">Attack Milestones & Progression</h3>
                    </div>
                    <div 
                      className="timeline-dropdown-pill"
                      onClick={() => setTimelineOrder(prev => prev === 'asc' ? 'desc' : 'asc')}
                      title="Click to toggle chronological ordering"
                      style={{ cursor: 'pointer' }}
                    >
                      <span>{timelineOrder === 'asc' ? 'Oldest First (Asc)' : 'Newest First (Desc)'}</span>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>

                  {/* DYNAMIC Progression Info calculated from incident events */}
                  <div className="phase-progress-info">
                    <div className="phase-title-text">
                      {progression.label}
                    </div>
                    <div className="phase-percent-text">
                      {progression.percent}% Progression (Phase {progression.phase} of 4)
                    </div>
                  </div>

                  {/* Horizontal Stepped Progress Bar (DYNAMIC) */}
                  <div className="stepped-track-wrapper">
                    <div className="stepped-track">
                      <div 
                        className="stepped-track-fill" 
                        style={{ width: `${progression.percent}%`, transition: 'width 0.4s ease' }}
                      ></div>
                    </div>
                    <div className="stepped-nodes-labels">
                      <span style={{ color: progression.phase >= 1 ? 'var(--text-ivory)' : '#64748b', fontWeight: progression.phase >= 1 ? 800 : 500 }}>
                        ● Initial Access
                      </span>
                      <span style={{ color: progression.phase >= 2 ? 'var(--text-ivory)' : '#64748b', fontWeight: progression.phase >= 2 ? 800 : 500 }}>
                        ● Execution
                      </span>
                      <span style={{ color: progression.phase >= 3 ? 'var(--text-ivory)' : '#64748b', fontWeight: progression.phase >= 3 ? 800 : 500 }}>
                        ● Persistence
                      </span>
                      <span style={{ color: progression.phase >= 4 ? 'var(--text-ivory)' : '#64748b', fontWeight: progression.phase >= 4 ? 800 : 500 }}>
                        ● C2 Egress
                      </span>
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
                  sortOrder={timelineOrder}
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

      {/* Floating Pending Response Actions Card with Working Approval Toggle */}
      {actions && actions.length > 0 && (
        <aside className="floating-pending-actions-card">
          <div className="floating-card-header">
            <h4 className="floating-card-title">Pending Containment Actions</h4>
            <span className="card-dots-menu" title="Autonomous Containment Queue">•••</span>
          </div>

          <div className="pending-actions-list-mini">
            {actions.slice(0, 3).map((act) => {
              const isApproved = approvedActionIds[act.id];

              return (
                <div 
                  key={act.id} 
                  onClick={() => toggleActionApproval(act.id)}
                  className={`pending-action-item-mini ${isApproved ? 'approved' : ''}`}
                  title="Click to approve/execute containment"
                  style={{ cursor: 'pointer' }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem', maxWidth: '240px' }}>
                    <span style={{ fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: isApproved ? '#34d399' : 'inherit' }}>
                      {act.description}
                    </span>
                    <span style={{ fontSize: '0.68rem', color: isApproved ? '#34d399' : '#94a3b8' }}>
                      {isApproved ? 'CONTAINMENT AUTHORIZED' : act.action_type}
                    </span>
                  </div>
                  <div className={`mini-check-pill ${isApproved ? 'checked' : ''}`}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  </div>
                </div>
              );
            })}
          </div>

          <div style={{ fontSize: '0.68rem', color: '#64748b', textAlign: 'center', paddingTop: '0.2rem' }}>
            Click item to sign dual-token analyst authorization
          </div>
        </aside>
      )}
    </div>
  );
}
