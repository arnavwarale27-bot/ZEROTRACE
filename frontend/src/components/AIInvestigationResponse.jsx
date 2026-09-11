import React, { useState, useEffect } from 'react';
import { fetchInvestigation, runAIInvestigation } from '../services/api';

export default function AIInvestigationResponse({ selectedIncidentId, selectedIncidentData }) {
  const [investigationData, setInvestigationData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);

  // Load existing investigation or auto-load when incident changes
  const loadInvestigation = async (incidentId) => {
    if (!incidentId) {
      setInvestigationData(null);
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await fetchInvestigation(incidentId);
      setInvestigationData(data);
    } catch (err) {
      setError(err.message || 'Failed to load AI investigation findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInvestigation(selectedIncidentId);
  }, [selectedIncidentId]);

  // Trigger new investigation via POST /api/v1/incidents/{incident_id}/investigate
  const handleTriggerInvestigation = async () => {
    if (!selectedIncidentId || generating) return;

    setGenerating(true);
    setError(null);
    try {
      const result = await runAIInvestigation(selectedIncidentId);
      // Backend returns { incident_id, investigation, recommended_actions, evidence_package }
      setInvestigationData({
        incident_id: result.incident_id,
        investigation: result.investigation,
        recommended_actions: result.recommended_actions,
        evidence_items: result.evidence_package?.evidence_items || [],
      });
    } catch (err) {
      setError(err.message || 'AI Investigation synthesis failed');
    } finally {
      setGenerating(false);
    }
  };

  const inv = investigationData?.investigation;
  const actions = investigationData?.recommended_actions || [];
  const evidenceItems = investigationData?.evidence_items || [];

  // Check if investigation has insufficient evidence
  const isInsufficientEvidence = 
    inv && ((inv.confidence_score !== undefined && inv.confidence_score < 0.2) || 
    (inv.summary && inv.summary.toLowerCase().includes('insufficient evidence')));

  // Helper for priority badges
  const getPriorityBadge = (priority) => {
    const p = (priority || '').toUpperCase();
    switch (p) {
      case 'CRITICAL':
        return { label: 'CRITICAL', bg: 'rgba(244,63,94,0.15)', color: '#f43f5e', border: 'rgba(244,63,94,0.35)' };
      case 'HIGH':
        return { label: 'HIGH', bg: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: 'rgba(245,158,11,0.35)' };
      case 'MEDIUM':
        return { label: 'MEDIUM', bg: 'rgba(59,130,246,0.15)', color: '#60a5fa', border: 'rgba(59,130,246,0.35)' };
      default:
        return { label: p || 'LOW', bg: 'rgba(148,163,184,0.15)', color: '#94a3b8', border: 'rgba(148,163,184,0.3)' };
    }
  };

  // Helper for action type labels
  const getActionTypeLabel = (type) => {
    const t = (type || '').toLowerCase();
    switch (t) {
      case 'isolate_host':
        return 'HOST ISOLATION';
      case 'revoke_credentials':
        return 'IDENTITY REVOCATION';
      case 'block_ip':
        return 'FIREWALL IP BLOCK';
      case 'block_domain':
        return 'DNS SINKHOLE BLOCK';
      case 'enhanced_monitoring':
        return 'TELEMETRY AUDITING';
      default:
        return t.toUpperCase().replace(/_/g, ' ');
    }
  };

  return (
    <section className="soc-section" id="ai-investigation-section" style={{ marginTop: '2.5rem', marginBottom: '4rem' }}>
      {/* Section Header */}
      <div className="section-header-banner" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span className="section-tag" style={{ background: 'rgba(168,85,247,0.2)', color: '#c084fc', borderColor: 'rgba(168,85,247,0.4)' }}>
              SECTION 4
            </span>
            <h2 className="section-title">AI INVESTIGATION & RESPONSE SYNTHESIS</h2>
          </div>
          <p className="section-subtitle">
            Evidence-grounded root cause analysis, uncertainty tracking, prioritized investigation steps, and SOC response remediation.
          </p>
        </div>

        {/* Action Button to Trigger AI Investigation */}
        {selectedIncidentId && (
          <button
            onClick={handleTriggerInvestigation}
            disabled={generating}
            className="ai-trigger-btn"
          >
            {generating ? (
              <>
                <div className="btn-spinner"></div>
                <span>Synthesizing Telemetry...</span>
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                  <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
                </svg>
                <span>{inv ? 'Re-run AI Investigation' : 'Generate AI Investigation'}</span>
              </>
            )}
          </button>
        )}
      </div>

      {!selectedIncidentId ? (
        <div className="card-glass" style={{ textAlign: 'center', padding: '3.5rem 2rem', color: '#64748b' }}>
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ margin: '0 auto 1rem' }}>
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <div style={{ fontSize: '1.05rem', fontWeight: 600, color: '#94a3b8' }}>No Incident Selected</div>
          <div style={{ fontSize: '0.875rem', marginTop: '0.25rem' }}>Select an incident in Section 1 to view or generate AI investigation findings.</div>
        </div>
      ) : loading ? (
        <div className="card-glass loading-state-box">
          <div className="spinner"></div>
          <span>Retrieving AI investigation record from backend...</span>
        </div>
      ) : error ? (
        <div className="card-glass error-state-box">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <span>{error}</span>
        </div>
      ) : !inv ? (
        <div className="card-glass empty-state-box" style={{ padding: '3.5rem 2rem' }}>
          <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="1.5">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
            <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
            <line x1="12" y1="22.08" x2="12" y2="12" />
          </svg>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', marginTop: '0.75rem' }}>
            No Investigation Generated Yet
          </div>
          <div style={{ fontSize: '0.875rem', color: '#94a3b8', maxWidth: '480px', margin: '0.5rem auto 1.5rem' }}>
            Click the button below to execute automated evidence packaging and generate an evidence-grounded AI investigation.
          </div>
          <button
            onClick={handleTriggerInvestigation}
            disabled={generating}
            className="ai-trigger-btn"
          >
            {generating ? 'Synthesizing Telemetry...' : 'Generate AI Investigation Now'}
          </button>
        </div>
      ) : (
        <div className="ai-workspace-layout">
          {/* ========================================================================= */}
          {/* SUBSECTION A: AI INVESTIGATION FINDINGS */}
          {/* ========================================================================= */}
          <div className="ai-main-card card-glass">
            <div className="ai-card-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                <div className="subsection-indicator ai-ind">A</div>
                <div>
                  <h3 className="subsection-title">AI INVESTIGATION FINDINGS</h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginTop: '0.2rem' }}>
                    <span className="inv-id-tag">{inv.id}</span>
                    <span className="inv-time-tag">
                      {inv.created_at ? new Date(inv.created_at).toLocaleString() : 'Just now'}
                    </span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div className="confidence-meter-pill">
                  <span className="conf-label">GROUNDED CONFIDENCE:</span>
                  <span className="conf-value">{Math.round((inv.confidence_score || 0) * 100)}%</span>
                </div>

                <span className={`inv-status-pill ${inv.status === 'COMPLETED' ? 'completed' : 'pending'}`}>
                  {inv.status}
                </span>
              </div>
            </div>

            {/* Insufficient Evidence Warning Banner if applicable */}
            {isInsufficientEvidence && (
              <div className="insufficient-evidence-alert">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <div>
                  <strong>INSUFFICIENT TELEMETRY EVIDENCE:</strong> Current telemetry volume is insufficient for definitive root cause attribution. Findings below represent tentative inferences only.
                </div>
              </div>
            )}

            {/* Synthesis Report Body */}
            <div className="ai-narrative-box">
              <div className="ai-markdown-render">
                {inv.summary ? (
                  inv.summary.split('\n').map((rawLine, idx) => {
                    const line = rawLine.trim();
                    if (!line) return null;

                    if (line.startsWith('### ')) {
                      return (
                        <h4 key={idx} className="ai-narrative-heading">
                          {line.replace('### ', '')}
                        </h4>
                      );
                    }

                    if (line.startsWith('- ')) {
                      const content = line.replace('- ', '');
                      return (
                        <div key={idx} className="ai-narrative-bullet">
                          <span className="bullet-dot">•</span>
                          <span>{content}</span>
                        </div>
                      );
                    }

                    return (
                      <p key={idx} className="ai-narrative-p">
                        {line}
                      </p>
                    );
                  })
                ) : (
                  <p className="ai-narrative-p">No synthesis summary provided.</p>
                )}
              </div>
            </div>

            {/* Supporting Evidence Package Overview */}
            <div className="ai-evidence-footer">
              <div className="evidence-footer-title">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                  <polyline points="10 9 9 9 8 9" />
                </svg>
                VERIFIED EVIDENCE ARTIFACTS ({inv.evidence_ids?.length || 0} ITEMS):
              </div>
              <div className="evidence-chips-row">
                {(inv.evidence_ids || []).map((evId) => (
                  <span key={evId} className="evidence-id-chip" title={evId}>
                    {evId}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Grid for Subsection B (Investigation Steps) & Subsection C (Response Actions) */}
          <div className="ai-actions-grid">
            {/* ========================================================================= */}
            {/* SUBSECTION B: NEXT INVESTIGATION STEPS */}
            {/* ========================================================================= */}
            <div className="ai-sub-card card-glass">
              <div className="subsection-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <div className="subsection-indicator steps-ind">B</div>
                  <div>
                    <h3 className="subsection-title">NEXT INVESTIGATION STEPS</h3>
                    <span className="subsection-count">Prioritized analyst follow-up recommendations</span>
                  </div>
                </div>
              </div>

              <div className="steps-list">
                <div className="step-card">
                  <div className="step-card-header">
                    <span className="step-num">01</span>
                    <span className="sev-chip" style={{ background: 'rgba(244,63,94,0.15)', color: '#f43f5e', border: '1px solid rgba(244,63,94,0.35)' }}>
                      CRITICAL
                    </span>
                    <span className="step-title-text">Host Process Tree & Memory Inspection</span>
                  </div>
                  <div className="step-body-text">
                    Inspect active processes and parent-child process lineage on targeted endpoint to confirm if injected shellcode or living-off-the-land binaries persist in memory.
                  </div>
                  <div className="step-meta-row">
                    <span className="step-reason-lbl">REASON: Verify persistence execution and memory artifacts</span>
                  </div>
                </div>

                <div className="step-card">
                  <div className="step-card-header">
                    <span className="step-num">02</span>
                    <span className="sev-chip" style={{ background: 'rgba(245,158,11,0.15)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.35)' }}>
                      HIGH
                    </span>
                    <span className="step-title-text">Authentication & Blast Radius Audit</span>
                  </div>
                  <div className="step-body-text">
                    Review directory authentication logs (Kerberos / NTLM / OAuth) for involved user accounts within +/- 4 hours of the initial detection timestamp.
                  </div>
                  <div className="step-meta-row">
                    <span className="step-reason-lbl">REASON: Assess credential exposure and detect unauthorized lateral pivot attempts</span>
                  </div>
                </div>

                <div className="step-card">
                  <div className="step-card-header">
                    <span className="step-num">03</span>
                    <span className="sev-chip" style={{ background: 'rgba(59,130,246,0.15)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.35)' }}>
                      MEDIUM
                    </span>
                    <span className="step-title-text">Network Perimeter Egress Analysis</span>
                  </div>
                  <div className="step-body-text">
                    Cross-reference firewall and NetFlow logs against proxy outbound connections to determine if secondary C2 channels were initiated.
                  </div>
                  <div className="step-meta-row">
                    <span className="step-reason-lbl">REASON: Fill missing telemetry gap regarding unobserved external egress</span>
                  </div>
                </div>
              </div>
            </div>

            {/* ========================================================================= */}
            {/* SUBSECTION C: RECOMMENDED RESPONSE ACTIONS */}
            {/* ========================================================================= */}
            <div className="ai-sub-card card-glass">
              <div className="subsection-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <div className="subsection-indicator response-ind">C</div>
                  <div>
                    <h3 className="subsection-title">RECOMMENDED RESPONSE ACTIONS</h3>
                    <span className="subsection-count">
                      {actions.length} Proposed Remediation Action{actions.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                </div>
              </div>

              {actions.length === 0 ? (
                <div className="empty-state-box">
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                  </svg>
                  <span>No automated response actions generated for this incident.</span>
                </div>
              ) : (
                <div className="actions-list">
                  {actions.map((act) => {
                    const priBadge = getPriorityBadge(act.priority);
                    const typeLabel = getActionTypeLabel(act.action_type);
                    const isAutomated = act.automated;

                    return (
                      <div key={act.id} className="response-action-card">
                        <div className="action-card-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                            <span
                              className="action-pri-badge"
                              style={{ backgroundColor: priBadge.bg, color: priBadge.color, border: `1px solid ${priBadge.border}` }}
                            >
                              {priBadge.label}
                            </span>
                            <span className="action-type-badge">
                              {typeLabel}
                            </span>
                          </div>

                          <span className="action-id-tag">{act.id}</span>
                        </div>

                        <div className="action-desc-text">
                          {act.description}
                        </div>

                        <div className="action-footer-row">
                          <div className="action-guardrail-badge">
                            {isAutomated ? (
                              <span className="guardrail-auto" title="Automated policy action">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                  <polyline points="20 6 9 17 4 12" />
                                </svg>
                                AUTOMATED POLICY ACTION
                              </span>
                            ) : (
                              <span className="guardrail-human" title="Requires human analyst confirmation">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                                  <circle cx="12" cy="12" r="10" />
                                  <line x1="12" y1="8" x2="12" y2="12" />
                                  <line x1="12" y1="16" x2="12.01" y2="16" />
                                </svg>
                                REQUIRES SOC ANALYST APPROVAL
                              </span>
                            )}
                          </div>

                          <div className="action-status-indicator">
                            STATUS: <span className="status-val">{act.status || 'PENDING APPROVAL'}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}

                  {/* Safety Guardrail Notice */}
                  <div className="soc-safety-notice">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    <span>
                      <strong>SOC SAFETY GUARDRAIL:</strong> In strict compliance with SOC containment policies, destructive actions (Host Isolation & Credential Revocation) are staged and require manual approval token before execution.
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
