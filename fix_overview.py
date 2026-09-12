import re

path = '/Users/arnav/ZEROTRACE/frontend/src/components/IncidentOverview.jsx'
with open(path, 'r') as f:
    content = f.read()

# Find everything from `  return (` to the end and replace it with the new minimal layout
new_return = """  return (
    <section id="section-incident-overview" className="section-incident-overview" style={{ width: '100%' }}>
      <div className="section-header-box" style={{ marginBottom: "2rem" }}>
        <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em", color: "var(--text-ivory)" }}>Incident Overview</h2>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '2rem', alignItems: 'start', width: '100%' }}>
        
        {/* 1. Active Incident List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--bg-border)', paddingBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Incidents Queue</span>
            <button onClick={() => loadIncidents()} disabled={loadingList} style={{ background: 'transparent', border: '1px solid var(--bg-border)', color: 'var(--text-ivory)', padding: '0.2rem 0.5rem', cursor: 'pointer', fontSize: '0.7rem' }}>
              {loadingList ? '...' : 'REFRESH'}
            </button>
          </div>

          {loadingList && <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Loading...</div>}
          {errorList && <div style={{ color: '#f43f5e', fontSize: '0.8rem' }}>Error: {errorList}</div>}
          
          {!loadingList && incidents.length === 0 && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No incidents found.</div>
          )}

          {!loadingList && incidents.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '600px', overflowY: 'auto' }}>
              {incidents.map((inc) => {
                const isSelected = (selectedIncidentData?.incident?.id || selectedIncidentId) === inc.id;
                const sevStyle = getSeverityStyle(inc.severity);
                return (
                  <div
                    key={inc.id}
                    onClick={() => handleSelect(inc.id)}
                    style={{
                      padding: '1rem',
                      border: isSelected ? '1px solid var(--text-ivory)' : '1px solid var(--bg-border)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.5rem',
                      background: 'transparent'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-ivory)' }}>{inc.id}</span>
                      <span style={{ fontSize: '0.65rem', color: sevStyle.color, border: `1px solid ${sevStyle.border}`, padding: '0.1rem 0.4rem', textTransform: 'uppercase' }}>{inc.severity}</span>
                    </div>
                    <div style={{ fontSize: '0.9rem', color: 'var(--text-ivory)', fontWeight: 600 }}>{inc.title}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{inc.status}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* 2. Selected Incident Details */}
        <div>
          {loadingDetails && <div style={{ color: 'var(--text-muted)', padding: '2rem' }}>Loading details...</div>}
          {errorDetails && <div style={{ color: '#f43f5e', padding: '2rem' }}>Error: {errorDetails}</div>}
          
          {!loadingDetails && !errorDetails && !incident && (
            <div style={{ color: 'var(--text-muted)', padding: '2rem', border: '1px solid var(--bg-border)' }}>Select an incident from the queue.</div>
          )}

          {!loadingDetails && !errorDetails && incident && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              
              <div>
                <div style={{ fontSize: 'clamp(4rem, 8vw, 8rem)', fontWeight: 900, lineHeight: 0.9, letterSpacing: '-0.05em', color: 'var(--text-ivory)' }}>
                  {incident.id}
                </div>
                <div style={{ marginTop: '1rem', fontSize: '1.25rem', color: 'var(--text-muted)' }}>
                  {incident.title}
                </div>
              </div>

              <div style={{ border: '1px solid var(--bg-border)', padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Severity</div>
                    <div style={{ color: getSeverityStyle(incident.severity).color, fontWeight: 700, fontSize: '1.5rem', textTransform: 'uppercase' }}>{incident.severity}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Status</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '1.5rem', textTransform: 'uppercase' }}>{incident.status}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Attack Window</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>{attackWindow}</div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--bg-border)', paddingTop: '1.5rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Affected Hosts</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '1rem' }}>{affectedHosts.length > 0 ? affectedHosts.join(', ') : 'None'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Affected Users</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '1rem' }}>{affectedUsers.length > 0 ? affectedUsers.join(', ') : 'None'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Extracted IOCs</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '1.5rem' }}>{extractedIOCs.size}</div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--bg-border)', paddingTop: '1.5rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Summary</div>
                  <div style={{ color: 'var(--text-muted)', lineHeight: 1.6, fontSize: '0.9rem' }}>
                    {incident.description || `Security incident ${incident.id} comprises ${events.length} correlated events on host ${affectedHosts.join(', ') || 'N/A'} with severity rating ${incident.severity}.`}
                  </div>
                </div>
              </div>

            </div>
          )}
        </div>
      </div>
    </section>
  );
}
"""

content = re.sub(r'  return \(\n.*', new_return, content, flags=re.DOTALL)

with open(path, 'w') as f:
    f.write(content)

print("IncidentOverview correctly refactored!")
