import React, { useState, useEffect } from 'react';
import { fetchIncidentTimeline, fetchEventById } from '../services/api';

export default function AttackInvestigation({ selectedIncidentId, selectedIncidentData }) {
  const [timeline, setTimeline] = useState([]);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [errorTimeline, setErrorTimeline] = useState(null);
  
  // Expanded event state
  const [expandedEventId, setExpandedEventId] = useState(null);
  const [eventDetails, setEventDetails] = useState({}); // { [eventId]: { loading, data, error } }

  // Load timeline whenever selected incident changes
  useEffect(() => {
    if (!selectedIncidentId) {
      setTimeline([]);
      setExpandedEventId(null);
      return;
    }

    const loadTimeline = async () => {
      setLoadingTimeline(true);
      setErrorTimeline(null);
      try {
        const data = await fetchIncidentTimeline(selectedIncidentId);
        // Ensure chronological ordering by timestamp
        const sorted = [...data].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        setTimeline(sorted);
        // Automatically expand first milestone if available
        if (sorted.length > 0 && !expandedEventId) {
          handleToggleEvent(sorted[0].source_event_id);
        }
      } catch (err) {
        setErrorTimeline(err.message || 'Failed to load attack timeline');
      } finally {
        setLoadingTimeline(false);
      }
    };

    loadTimeline();
  }, [selectedIncidentId]);

  // Expand / collapse and fetch real event raw_data
  const handleToggleEvent = async (sourceEventId) => {
    if (!sourceEventId) return;

    if (expandedEventId === sourceEventId) {
      setExpandedEventId(null);
      return;
    }

    setExpandedEventId(sourceEventId);

    // If not already fetched, load from GET /api/v1/events/{event_id}
    if (!eventDetails[sourceEventId]?.data && !eventDetails[sourceEventId]?.loading) {
      setEventDetails(prev => ({
        ...prev,
        [sourceEventId]: { loading: true, data: null, error: null }
      }));

      try {
        const fullEvent = await fetchEventById(sourceEventId);
        setEventDetails(prev => ({
          ...prev,
          [sourceEventId]: { loading: false, data: fullEvent, error: null }
        }));
      } catch (err) {
        setEventDetails(prev => ({
          ...prev,
          [sourceEventId]: { loading: false, data: null, error: err.message || 'Failed to fetch event details' }
        }));
      }
    }
  };

  // Helper for severity badge colors
  const getSeverityBadge = (sev) => {
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
    <section id="section-attack-investigation" className="section-attack-investigation">
      <div className="section-header-box">
        <div className="section-badge-tag">SECTION 02</div>
        <h2 className="section-main-heading">Attack Investigation & Timeline</h2>
        <p className="section-sub-text">
          Chronological sequence of verified telemetry milestones reconstructed from database security events for Incident <span className="mono-highlight">{selectedIncidentId || 'None'}</span>.
        </p>
      </div>

      <div className="timeline-container-card">
        
        {/* Loading State */}
        {loadingTimeline && (
          <div className="state-notice" style={{ minHeight: '280px' }}>
            <span className="spinner-dot"></span>
            Reconstructing attack progression timeline from telemetry events...
          </div>
        )}

        {/* Error State */}
        {errorTimeline && (
          <div className="state-notice error" style={{ minHeight: '280px' }}>
            <strong>Timeline API Error:</strong> {errorTimeline}
          </div>
        )}

        {/* Empty State */}
        {!loadingTimeline && !errorTimeline && timeline.length === 0 && (
          <div className="state-notice empty" style={{ minHeight: '280px' }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>⏱️</div>
            <h3>No Timeline Events Available</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No correlated timeline milestones exist for this incident.
            </p>
          </div>
        )}

        {/* Active Chronological Timeline */}
        {!loadingTimeline && !errorTimeline && timeline.length > 0 && (
          <div className="timeline-stream">
            {timeline.map((item, idx) => {
              const isExpanded = expandedEventId === item.source_event_id;
              const detailObj = eventDetails[item.source_event_id];
              const fullEvent = detailObj?.data;

              // Extract parameter values (either from loaded event or description)
              const rawData = fullEvent?.raw_data || {};
              const hostVal = fullEvent?.host || rawData.Computer || rawData.hostname || 'Unspecified';
              const userVal = fullEvent?.user || rawData.TargetUserName || rawData.username || 'Unspecified';
              const ipVal = rawData.IpAddress || rawData.DestinationIp || rawData.SourceIp || rawData.ClientIP || null;
              const procVal = rawData.process_name || rawData.ProcessName || rawData.TargetProcess || null;
              const sevVal = fullEvent?.severity || 'MEDIUM';
              const attackStage = fullEvent?.attack_stage || 'Execution';
              const attackId = fullEvent?.attack_id || null;

              const sevStyle = getSeverityBadge(sevVal);

              return (
                <div key={item.id || idx} className={`timeline-node ${isExpanded ? 'expanded' : ''}`}>
                  
                  {/* Left Rail / Sequence Pillar */}
                  <div className="timeline-rail">
                    <div className="rail-marker">
                      <span className="seq-badge">#{item.sequence + 1}</span>
                    </div>
                    {idx < timeline.length - 1 && <div className="rail-line"></div>}
                  </div>

                  {/* Main Event Milestone Card */}
                  <div className="timeline-card-content">
                    
                    {/* Header Row */}
                    <div 
                      className="milestone-header-clickable"
                      onClick={() => handleToggleEvent(item.source_event_id)}
                    >
                      <div className="milestone-title-col">
                        <div className="milestone-meta-pills">
                          <span className="source-tag">[{item.title.split(']')[0].replace('[', '')}]</span>
                          <span 
                            className="sev-chip"
                            style={{ background: sevStyle.bg, color: sevStyle.color, border: `1px solid ${sevStyle.border}` }}
                          >
                            {sevVal}
                          </span>
                          <span className="nature-chip observed">OBSERVED TELEMETRY</span>
                          <span className="timestamp-mono">
                            {new Date(item.timestamp).toISOString().replace('T', ' ').slice(0, 19)}Z
                          </span>
                        </div>
                        
                        <h4 className="milestone-title-text">{item.title}</h4>
                      </div>

                      <div className="milestone-toggle-btn">
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                          {isExpanded ? 'Hide Raw' : 'Inspect Telemetry'}
                        </span>
                        <svg 
                          width="16" 
                          height="16" 
                          viewBox="0 0 24 24" 
                          fill="none" 
                          stroke="currentColor" 
                          strokeWidth="2.5"
                          style={{ transform: isExpanded ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }}
                        >
                          <path d="M6 9l6 6 6-6" />
                        </svg>
                      </div>
                    </div>

                    {/* Description */}
                    <p className="milestone-desc-text">
                      {item.description}
                    </p>

                    {/* Parameter Attributes Grid */}
                    <div className="milestone-params-grid">
                      <div className="param-item">
                        <span className="param-lbl">EVENT ID</span>
                        <span className="param-val mono-cyan">{item.source_event_id}</span>
                      </div>

                      <div className="param-item">
                        <span className="param-lbl">EVENT TYPE</span>
                        <span className="param-val">{item.event_type}</span>
                      </div>

                      <div className="param-item">
                        <span className="param-lbl">HOST</span>
                        <span className="param-val">{hostVal}</span>
                      </div>

                      <div className="param-item">
                        <span className="param-lbl">USER</span>
                        <span className="param-val">{userVal}</span>
                      </div>

                      {ipVal && (
                        <div className="param-item">
                          <span className="param-lbl">IP ADDRESS</span>
                          <span className="param-val mono-val">{ipVal}</span>
                        </div>
                      )}

                      {procVal && (
                        <div className="param-item">
                          <span className="param-lbl">PROCESS</span>
                          <span className="param-val mono-val">{procVal}</span>
                        </div>
                      )}

                      <div className="param-item">
                        <span className="param-lbl">ATTACK STAGE</span>
                        <span className="param-val" style={{ color: '#fbbf24' }}>{attackStage}</span>
                      </div>

                      {attackId && (
                        <div className="param-item">
                          <span className="param-lbl">MITRE ATTACK ID</span>
                          <span className="param-val mono-cyan">{attackId}</span>
                        </div>
                      )}

                      <div className="param-item">
                        <span className="param-lbl">EVIDENCE REF</span>
                        <span className="param-val mono-val">{item.id}</span>
                      </div>
                    </div>

                    {/* Expanded Telemetry & Raw Data Viewer */}
                    {isExpanded && (
                      <div className="raw-telemetry-expand-box">
                        <div className="raw-box-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <polyline points="16 18 22 12 16 6" />
                              <polyline points="8 6 2 12 8 18" />
                            </svg>
                            <span>Canonical SecurityEvent & Preserved raw_data</span>
                          </div>
                          <span className="mono-tag-pill">{item.source_event_id}</span>
                        </div>

                        {detailObj?.loading && (
                          <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                            <span className="spinner-dot" style={{ width: '14px', height: '14px', marginBottom: '0.4rem' }}></span>
                            Fetching normalized event payload from GET /api/v1/events/{item.source_event_id}...
                          </div>
                        )}

                        {detailObj?.error && (
                          <div style={{ padding: '1rem', color: '#fb7185', fontSize: '0.85rem' }}>
                            <strong>Error loading event payload:</strong> {detailObj.error}
                          </div>
                        )}

                        {fullEvent && (
                          <div className="json-code-view">
                            <pre>{JSON.stringify(fullEvent, null, 2)}</pre>
                          </div>
                        )}
                      </div>
                    )}

                  </div>
                </div>
              );
            })}
          </div>
        )}

      </div>
    </section>
  );
}
