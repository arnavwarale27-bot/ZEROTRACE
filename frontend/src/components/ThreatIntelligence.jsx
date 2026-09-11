import React, { useState, useEffect } from 'react';
import { fetchIOCs, fetchIncidentMitre } from '../services/api';

export default function ThreatIntelligence({ selectedIncidentId, selectedIncidentData }) {
  // IOC State
  const [allIocs, setAllIocs] = useState([]);
  const [loadingIocs, setLoadingIocs] = useState(false);
  const [errorIocs, setErrorIocs] = useState(null);
  const [selectedTypeFilter, setSelectedTypeFilter] = useState('ALL');
  const [copiedValue, setCopiedValue] = useState(null);

  // MITRE State
  const [mitreTechniques, setMitreTechniques] = useState([]);
  const [loadingMitre, setLoadingMitre] = useState(false);
  const [errorMitre, setErrorMitre] = useState(null);

  // Active incident event IDs
  const incidentEventIds = selectedIncidentData?.incident?.event_ids || 
    (selectedIncidentData?.events ? selectedIncidentData.events.map(e => e.event_id) : []);

  // Fetch IOCs and MITRE mappings when selectedIncidentId changes
  useEffect(() => {
    if (!selectedIncidentId) {
      setAllIocs([]);
      setMitreTechniques([]);
      return;
    }

    // 1. Fetch IOCs from GET /api/v1/iocs
    const loadIocs = async () => {
      setLoadingIocs(true);
      setErrorIocs(null);
      try {
        const data = await fetchIOCs();
        setAllIocs(data || []);
      } catch (err) {
        setErrorIocs(err.message || 'Failed to fetch threat intelligence IOCs');
      } finally {
        setLoadingIocs(false);
      }
    };

    // 2. Fetch MITRE mappings from GET /api/v1/incidents/{incident_id}/mitre
    const loadMitre = async () => {
      setLoadingMitre(true);
      setErrorMitre(null);
      try {
        const data = await fetchIncidentMitre(selectedIncidentId);
        setMitreTechniques(data || []);
      } catch (err) {
        setErrorMitre(err.message || 'Failed to fetch MITRE ATT&CK mappings');
      } finally {
        setLoadingMitre(false);
      }
    };

    loadIocs();
    loadMitre();
  }, [selectedIncidentId]);

  // Filter IOCs associated with current selected incident
  const associatedIocs = allIocs.filter(ioc => {
    // 1. Check if direct ioc_ids on incident includes this IOC
    if (selectedIncidentData?.incident?.ioc_ids?.includes(ioc.id)) {
      return true;
    }
    // 2. Check if related_event_ids in IOC metadata overlap with incident event_ids
    const relatedEvents = ioc.metadata?.related_event_ids || [];
    if (relatedEvents.some(eid => incidentEventIds.includes(eid))) {
      return true;
    }
    return false;
  });

  // Apply type filter
  const filteredIocs = associatedIocs.filter(ioc => {
    if (selectedTypeFilter === 'ALL') return true;
    const type = (ioc.type || '').toLowerCase();
    if (selectedTypeFilter === 'IP') return type === 'ip';
    if (selectedTypeFilter === 'DOMAIN') return type === 'domain';
    if (selectedTypeFilter === 'HASH') return ['sha256', 'md5', 'sha1', 'hash'].includes(type);
    if (selectedTypeFilter === 'USERNAME') return type === 'username';
    if (selectedTypeFilter === 'HOSTNAME') return type === 'hostname';
    if (selectedTypeFilter === 'PROCESS') return type === 'process';
    return true;
  });

  // Copy helper
  const handleCopy = (val) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Helper for reputation badge styling
  const getReputationBadge = (reputation, status) => {
    const rep = (reputation || '').toLowerCase();
    const st = (status || '').toLowerCase();

    if (rep === 'malicious') {
      return { label: 'MALICIOUS', bg: 'rgba(244,63,94,0.15)', color: '#f43f5e', border: 'rgba(244,63,94,0.4)' };
    }
    if (rep === 'suspicious') {
      return { label: 'SUSPICIOUS', bg: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: 'rgba(245,158,11,0.4)' };
    }
    if (rep === 'benign') {
      return { label: 'BENIGN', bg: 'rgba(16,185,129,0.15)', color: '#10b981', border: 'rgba(16,185,129,0.4)' };
    }
    if (st === 'unavailable') {
      return { label: 'UNAVAILABLE', bg: 'rgba(148,163,184,0.1)', color: '#94a3b8', border: 'rgba(148,163,184,0.3)' };
    }
    return { label: 'UNKNOWN', bg: 'rgba(100,116,139,0.1)', color: '#94a3b8', border: 'rgba(100,116,139,0.3)' };
  };

  // Helper for IOC type badges
  const getTypeBadge = (type) => {
    const t = (type || '').toLowerCase();
    switch (t) {
      case 'ip':
        return { label: 'IP ADDRESS', bg: 'rgba(56,189,248,0.15)', color: '#38bdf8' };
      case 'domain':
        return { label: 'DOMAIN', bg: 'rgba(168,85,247,0.15)', color: '#a855f7' };
      case 'sha256':
      case 'md5':
      case 'hash':
        return { label: t.toUpperCase(), bg: 'rgba(236,72,153,0.15)', color: '#ec4899' };
      case 'username':
        return { label: 'USER IDENTITY', bg: 'rgba(34,197,94,0.15)', color: '#22c55e' };
      case 'hostname':
        return { label: 'ENDPOINT HOST', bg: 'rgba(251,191,36,0.15)', color: '#fbbf24' };
      case 'process':
        return { label: 'PROCESS EXEC', bg: 'rgba(239,68,68,0.15)', color: '#ef4444' };
      default:
        return { label: t.toUpperCase(), bg: 'rgba(148,163,184,0.15)', color: '#cbd5e1' };
    }
  };

  return (
    <section className="soc-section" id="threat-intelligence-section" style={{ marginTop: '2rem' }}>
      {/* Section Header */}
      <div className="section-header-banner">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span className="section-tag">SECTION 3</span>
          <h2 className="section-title">THREAT INTELLIGENCE & MITRE MATRIX</h2>
        </div>
        <p className="section-subtitle">
          Correlated Indicators of Compromise (IOCs), verified threat intelligence enrichment, and MITRE ATT&CK technique mapping.
        </p>
      </div>

      {!selectedIncidentId ? (
        <div className="card-glass" style={{ textAlign: 'center', padding: '3.5rem 2rem', color: '#64748b' }}>
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ margin: '0 auto 1rem' }}>
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <div style={{ fontSize: '1.05rem', fontWeight: 600, color: '#94a3b8' }}>No Incident Selected</div>
          <div style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>Select an incident in Section 1 to inspect correlated IOCs and MITRE ATT&CK techniques.</div>
        </div>
      ) : (
        <div className="threat-intel-grid">
          {/* ========================================================================= */}
          {/* SUBSECTION A: IOC INTELLIGENCE */}
          {/* ========================================================================= */}
          <div className="threat-intel-panel card-glass">
            <div className="subsection-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <div className="subsection-indicator">A</div>
                <div>
                  <h3 className="subsection-title">IOC INTELLIGENCE</h3>
                  <span className="subsection-count">
                    {associatedIocs.length} Extracted Indicator{associatedIocs.length !== 1 ? 's' : ''}
                  </span>
                </div>
              </div>

              {/* Type Filter Buttons */}
              <div className="ioc-filter-pills">
                {['ALL', 'IP', 'DOMAIN', 'HASH', 'USERNAME', 'HOSTNAME', 'PROCESS'].map((filterKey) => (
                  <button
                    key={filterKey}
                    onClick={() => setSelectedTypeFilter(filterKey)}
                    className={`ioc-filter-btn ${selectedTypeFilter === filterKey ? 'active' : ''}`}
                  >
                    {filterKey}
                  </button>
                ))}
              </div>
            </div>

            {/* IOC Content Area */}
            <div className="subsection-body">
              {loadingIocs ? (
                <div className="loading-state-box">
                  <div className="spinner"></div>
                  <span>Retrieving IOC entities and threat intelligence records...</span>
                </div>
              ) : errorIocs ? (
                <div className="error-state-box">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  <span>{errorIocs}</span>
                </div>
              ) : filteredIocs.length === 0 ? (
                <div className="empty-state-box">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                  <span>No {selectedTypeFilter !== 'ALL' ? selectedTypeFilter : ''} IOCs identified for this incident.</span>
                </div>
              ) : (
                <div className="ioc-cards-list">
                  {filteredIocs.map((ioc) => {
                    const localEnrich = ioc.metadata?.enrichment?.local;
                    const extEnrich = ioc.metadata?.enrichment?.external;
                    const reputation = ioc.metadata?.enrichment?.reputation || localEnrich?.reputation || 'unknown';
                    const enrichStatus = ioc.metadata?.enrichment?.status || localEnrich?.status || 'unknown';
                    const repBadge = getReputationBadge(reputation, enrichStatus);
                    const typeBadge = getTypeBadge(ioc.type);
                    const relatedEvents = ioc.metadata?.related_event_ids || [];
                    const provider = localEnrich?.provider 
                      ? (extEnrich?.status === 'unavailable' ? `${localEnrich.provider} (External Intel Unconfigured)` : localEnrich.provider)
                      : (extEnrich?.provider || 'local_extraction');
                    const enrichedAt = ioc.metadata?.enrichment?.enriched_at || ioc.last_seen;

                    return (
                      <div key={ioc.id} className="ioc-card">
                        <div className="ioc-card-top">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                            <span 
                              className="ioc-type-badge" 
                              style={{ backgroundColor: typeBadge.bg, color: typeBadge.color }}
                            >
                              {typeBadge.label}
                            </span>
                            <span 
                              className="ioc-rep-badge" 
                              style={{ backgroundColor: repBadge.bg, color: repBadge.color, border: `1px solid ${repBadge.border}` }}
                            >
                              {repBadge.label}
                            </span>
                            <span className="ioc-conf-badge">
                              CONFIDENCE: {Math.round((ioc.confidence_score || 0) * 100)}%
                            </span>
                          </div>

                          <span className="ioc-id-pill">{ioc.id}</span>
                        </div>

                        {/* Value with Copy Action */}
                        <div className="ioc-value-row">
                          <div className="ioc-value-text" title={ioc.value}>
                            {ioc.value}
                          </div>
                          <button
                            onClick={() => handleCopy(ioc.value)}
                            className="ioc-copy-btn"
                            title="Copy to clipboard"
                          >
                            {copiedValue === ioc.value ? (
                              <span style={{ color: '#10b981', fontSize: '0.75rem', fontWeight: 600 }}>COPIED</span>
                            ) : (
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                              </svg>
                            )}
                          </button>
                        </div>

                        {/* Enrichment Meta Details */}
                        <div className="ioc-meta-grid">
                          <div className="ioc-meta-item">
                            <span className="ioc-meta-label">PROVIDER / SOURCE</span>
                            <span className="ioc-meta-val">{provider}</span>
                          </div>

                          <div className="ioc-meta-item">
                            <span className="ioc-meta-label">ENRICHED TIMESTAMP</span>
                            <span className="ioc-meta-val">
                              {enrichedAt ? new Date(enrichedAt).toLocaleString() : 'N/A'}
                            </span>
                          </div>
                        </div>

                        {/* Related Events Chips */}
                        {relatedEvents.length > 0 && (
                          <div className="ioc-related-events">
                            <span className="ioc-meta-label">RELATED EVENTS ({relatedEvents.length}):</span>
                            <div className="ioc-event-chips">
                              {relatedEvents.map((eid) => (
                                <span key={eid} className="ioc-event-chip" title={eid}>
                                  {eid}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Tags */}
                        {ioc.tags && ioc.tags.length > 0 && (
                          <div className="ioc-tags-row">
                            {ioc.tags.map((tag, idx) => (
                              <span key={idx} className="ioc-tag-chip">
                                #{tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SUBSECTION B: MITRE ATT&CK */}
          {/* ========================================================================= */}
          <div className="threat-intel-panel card-glass">
            <div className="subsection-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <div className="subsection-indicator mitre-ind">B</div>
                <div>
                  <h3 className="subsection-title">MITRE ATT&CK FRAMEWORK</h3>
                  <span className="subsection-count">
                    {mitreTechniques.length} Mapped Technique{mitreTechniques.length !== 1 ? 's' : ''}
                  </span>
                </div>
              </div>
            </div>

            {/* MITRE Content Area */}
            <div className="subsection-body">
              {loadingMitre ? (
                <div className="loading-state-box">
                  <div className="spinner"></div>
                  <span>Mapping incident events to MITRE ATT&CK matrix...</span>
                </div>
              ) : errorMitre ? (
                <div className="error-state-box">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                  </svg>
                  <span>{errorMitre}</span>
                </div>
              ) : mitreTechniques.length === 0 ? (
                <div className="empty-state-box">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
                    <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
                  </svg>
                  <span>No MITRE ATT&CK techniques mapped for this incident.</span>
                </div>
              ) : (
                <div className="mitre-cards-list">
                  {mitreTechniques.map((tech) => {
                    const isObserved = (tech.evidence_nature || '').toLowerCase() === 'observed';
                    const supportingEvents = tech.supporting_event_ids || [];

                    return (
                      <div key={tech.technique_id} className="mitre-card">
                        <div className="mitre-card-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <a
                              href={tech.url || `https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}/`}
                              target="_blank"
                              rel="noreferrer"
                              className="mitre-id-badge"
                              title="View MITRE ATT&CK documentation"
                            >
                              {tech.technique_id}
                              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginLeft: '4px' }}>
                                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                                <polyline points="15 3 21 3 21 9" />
                                <line x1="10" y1="14" x2="21" y2="3" />
                              </svg>
                            </a>

                            <span className="mitre-tactic-badge">
                              {tech.tactic}
                            </span>
                          </div>

                          {/* Observed vs Inferred Status Badge */}
                          <span
                            className={`mitre-nature-badge ${isObserved ? 'observed' : 'inferred'}`}
                            title={isObserved ? 'Direct telemetry evidence observed' : 'Inferred via behavioral rule correlation'}
                          >
                            <span className="nature-dot"></span>
                            {isObserved ? 'OBSERVED' : 'INFERRED'}
                          </span>
                        </div>

                        {/* Technique Name */}
                        <div className="mitre-name-text">
                          {tech.name}
                        </div>

                        {/* Description */}
                        {tech.description && (
                          <div className="mitre-desc-text">
                            {tech.description}
                          </div>
                        )}

                        {/* Supporting Event Evidence */}
                        <div className="mitre-supporting-evidence">
                          <div className="mitre-evidence-title">
                            SUPPORTING EVIDENCE ({supportingEvents.length} EVENT{supportingEvents.length !== 1 ? 'S' : ''}):
                          </div>
                          <div className="mitre-event-chips">
                            {supportingEvents.map((eid) => (
                              <span key={eid} className="mitre-event-chip" title={eid}>
                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                                </svg>
                                {eid}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
