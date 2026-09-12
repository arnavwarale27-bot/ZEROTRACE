import React, { useState, useEffect } from 'react';
import { fetchIncidentTimeline, fetchEventById } from '../services/api';

export default function AttackInvestigation({ selectedIncidentId, selectedIncidentData, sortOrder = 'asc' }) {
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
        const sorted = [...data].sort((a, b) => {
          const diff = new Date(a.timestamp) - new Date(b.timestamp);
          return sortOrder === 'desc' ? -diff : diff;
        });
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
  }, [selectedIncidentId, sortOrder]);

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
      <div className="section-header-box" style={{ marginBottom: "2rem" }}>
        <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em" }}>Attack Timeline</h2>
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
                <div key={item.id || idx} style={{ borderBottom: '1px solid var(--bg-border)', padding: '1.5rem 0', display: 'flex', gap: '1.5rem', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', cursor: 'pointer' }} onClick={() => handleToggleEvent(item.source_event_id)}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(item.timestamp).toISOString().replace('T', ' ').slice(0, 19)}Z
                      </div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-ivory)' }}>
                        {item.title}
                      </div>
                    </div>
                    <div style={{ padding: '0.2rem 0.5rem', border: '1px solid var(--bg-border)', fontSize: '0.7rem', color: sevStyle.color, textTransform: 'uppercase' }}>
                      {sevVal}
                    </div>
                  </div>
                  
                  {isExpanded && (
                    <div style={{ padding: '1rem', border: '1px solid var(--bg-border)', background: 'transparent' }}>
                      <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1rem', lineHeight: 1.5 }}>{item.description}</p>
                      
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
                        <div><span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Event ID</span><span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>{item.source_event_id}</span></div>
                        <div><span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Type</span><span style={{ fontSize: '0.8rem' }}>{item.event_type}</span></div>
                        <div><span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Host</span><span style={{ fontSize: '0.8rem' }}>{hostVal}</span></div>
                        <div><span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>User</span><span style={{ fontSize: '0.8rem' }}>{userVal}</span></div>
                        <div><span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Stage</span><span style={{ fontSize: '0.8rem', color: 'var(--accent-amber)' }}>{attackStage}</span></div>
                      </div>
                      
                      {detailObj?.loading && <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Loading raw telemetry...</div>}
                      {fullEvent && (
                        <pre style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', overflowX: 'auto', padding: '1rem', borderTop: '1px solid var(--bg-border)' }}>
                          {JSON.stringify(fullEvent, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

      </div>
    </section>
  );
}
