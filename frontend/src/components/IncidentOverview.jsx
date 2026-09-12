import React, { useState, useEffect } from 'react';
import { fetchIncidents, fetchIncidentById } from '../services/api';

export default function IncidentOverview({
  selectedIncidentId,
  onSelectIncident,
  selectedIncidentData,
  setSelectedIncidentData,
}) {
  const [incidents, setIncidents] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [errorList, setErrorList] = useState(null);
  const [errorDetails, setErrorDetails] = useState(null);

  // Load active incident list from GET /api/v1/incidents
  const loadIncidents = async (preferredId = null) => {
    setLoadingList(true);
    setErrorList(null);
    try {
      const list = await fetchIncidents();
      setIncidents(list);
      if (list.length > 0) {
        const idToSelect = preferredId || (list.some(i => i.id === selectedIncidentId) ? selectedIncidentId : list[0].id);
        handleSelect(idToSelect);
      } else {
        setSelectedIncidentData(null);
        if (onSelectIncident) onSelectIncident(null);
      }
    } catch (err) {
      setErrorList(err.message || 'Failed to load incidents from server');
    } finally {
      setLoadingList(false);
    }
  };

  // Load selected incident details from GET /api/v1/incidents/{incident_id}
  const handleSelect = async (incidentId) => {
    if (!incidentId) return;
    if (onSelectIncident) onSelectIncident(incidentId);
    setLoadingDetails(true);
    setErrorDetails(null);
    try {
      const data = await fetchIncidentById(incidentId);
      setSelectedIncidentData(data);
    } catch (err) {
      setErrorDetails(err.message || `Failed to load details for incident ${incidentId}`);
    } finally {
      setLoadingDetails(false);
    }
  };

  useEffect(() => {
    loadIncidents(selectedIncidentId);
  }, []);

  // Compute metrics from real events
  const incident = selectedIncidentData?.incident;
  const events = selectedIncidentData?.events || [];

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

  // Calculate highest confidence score
  const maxConfidence = events.reduce((max, e) => Math.max(max, e.confidence || 0), 0);

  const getSeverityStyle = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL':
        return { bg: 'rgba(244,63,94,0.15)', color: '#f43f5e', border: 'rgba(244,63,94,0.35)' };
      case 'HIGH':
        return { bg: 'rgba(245,158,11,0.15)', color: '#fbbf24', border: 'rgba(245,158,11,0.35)' };
      case 'MEDIUM':
        return { bg: 'rgba(59,130,246,0.15)', color: '#60a5fa', border: 'rgba(59,130,246,0.35)' };
      case 'LOW':
        return { bg: 'rgba(16,185,129,0.15)', color: '#34d399', border: 'rgba(16,185,129,0.35)' };
      default:
        return { bg: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: 'rgba(148,163,184,0.35)' };
    }
  };

  return (
    <section id="section-incident-overview" className="section-incident-overview">
      <div className="section-header-box" style={{ marginBottom: "2rem" }}>
  <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em" }}>Incident Overview</h2>
</div>
        <h2 className="section-main-heading">Incident Overview & Triage</h2>
        <p className="section-sub-text">
          Real-time incident queue correlated from database telemetry events. Select an incident to inspect its attack parameters.
        </p>
      </div>

      <div className="incident-grid-layout">
        
        {/* 1. Active Incident List */}
        <div className="incident-list-panel">
          <div className="panel-top-bar">
            <div className="panel-heading">
              <span>Active Incidents</span>
              <span className="count-pill">{incidents.length}</span>
            </div>
            <button 
              onClick={() => loadIncidents()} 
              className="refresh-btn" 
              title="Refresh Incidents from API"
              disabled={loadingList}
            >
              {loadingList ? '...' : '↻'}
            </button>
          </div>

          {/* Loading State */}
          {loadingList && (
            <div className="state-notice">
              <span className="spinner-dot"></span>
              Loading active incidents from API...
            </div>
          )}

          {/* Error State */}
          {errorList && (
            <div className="state-notice error">
              <strong>Error:</strong> {errorList}
            </div>
          )}

          {/* Empty State */}
          {!loadingList && !errorList && incidents.length === 0 && (
            <div className="state-notice empty">
              <div style={{ fontSize: '1.75rem', marginBottom: '0.4rem' }}>🛡️</div>
              <strong>No incidents found.</strong>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Run correlation or ingest logs to generate security incidents.
              </p>
            </div>
          )}

          {/* Incident Cards */}
          {!loadingList && incidents.length > 0 && (
            <div className="incident-cards-scroll">
              {incidents.map((inc) => {
                const isSelected = (selectedIncidentData?.incident?.id || selectedIncidentId) === inc.id;
                const sevStyle = getSeverityStyle(inc.severity);
                return (
                  <div
                    key={inc.id}
                    onClick={() => handleSelect(inc.id)}
                    className={`incident-list-item ${isSelected ? 'selected' : ''}`}
                  >
                    <div className="item-row-top">
                      <span className="inc-id-tag">{inc.id}</span>
                      <span 
                        className="inc-sev-badge"
                        style={{ background: sevStyle.bg, color: sevStyle.color, border: `1px solid ${sevStyle.border}` }}
                      >
                        {inc.severity}
                      </span>
                    </div>

                    <div className="inc-title-text">
                      {inc.title}
                    </div>

                    <div className="item-row-bottom">
                      <span className="inc-status-tag">Status: <strong>{inc.status}</strong></span>
                      <span className="inc-time-tag">
                        {inc.created_at ? new Date(inc.created_at).toLocaleTimeString() : 'Recent'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* 2. Selected Incident Overview & Details */}
        <div className="incident-details-panel">
          {loadingDetails && (
            <div className="state-notice" style={{ minHeight: '340px' }}>
              <span className="spinner-dot"></span>
              Loading incident telemetry details...
            </div>
          )}

          {errorDetails && (
            <div className="state-notice error" style={{ minHeight: '340px' }}>
              <strong>Failed to load incident details:</strong> {errorDetails}
            </div>
          )}

          {!loadingDetails && !errorDetails && !incident && (
            <div className="state-notice empty" style={{ minHeight: '340px' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🔍</div>
              <h3>Select an incident</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Choose an incident from the queue on the left to inspect its parameters.
              </p>
            </div>
          )}

          {!loadingDetails && !errorDetails && incident && (
            <div className="incident-overview-body">
              
              {/* Header Info */}
              <div className="overview-header-row">
                <div>
                  <div className="meta-pill-group">
                    <span className="inc-id-hero">{incident.id}</span>
                    <span 
                      className="inc-sev-badge-large"
                      style={{ 
                        background: getSeverityStyle(incident.severity).bg, 
                        color: getSeverityStyle(incident.severity).color, 
                        border: `1px solid ${getSeverityStyle(incident.severity).border}` 
                      }}
                    >
                      {incident.severity}
                    </span>
                    <span className="inc-status-pill">
                      ● {incident.status}
                    </span>
                  </div>
                  
                  <h3 className="overview-title-heading">{incident.title}</h3>
                </div>
              </div>

              {/* Parameter Metrics Grid */}
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
                    {events.length > 0 ? events.length : (incident.event_ids?.length || 0)}
                  </div>
                </div>

                <div className="metric-box">
                  <div className="metric-box-label">EXTRACTED IOCs</div>
                  <div className="metric-box-value highlight-num">
                    {extractedIOCs.size}
                  </div>
                </div>

                <div className="metric-box">
                  <div className="metric-box-label">CONFIDENCE</div>
                  <div className="metric-box-value" style={{ color: maxConfidence > 0.8 ? '#34d399' : '#fbbf24' }}>
                    {maxConfidence > 0 ? `${Math.round(maxConfidence * 100)}%` : 'Calculated'}
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
                  {incident.description || `Security incident ${incident.id} comprises ${events.length} correlated events on host ${affectedHosts.join(', ') || 'N/A'} with severity rating ${incident.severity}.`}
                </p>
              </div>

            </div>
          )}
        </div>

      </div>
    </section>
  );
}
