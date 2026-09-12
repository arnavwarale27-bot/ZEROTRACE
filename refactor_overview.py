import re

path = '/Users/arnav/ZEROTRACE/frontend/src/components/IncidentOverview.jsx'
with open(path, 'r') as f:
    content = f.read()

# 1. Remove Section 01 · Overview redundancy
content = re.sub(
    r'<div className="section-header-box">.*?</div>',
    '<div className="section-header-box" style={{ marginBottom: "2rem" }}>\n  <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em" }}>Incident Overview</h2>\n</div>',
    content, flags=re.DOTALL
)

# 2. Refactor the metrics grid and header info
new_details_panel = """          {!loadingDetails && !errorDetails && incident && (
            <div className="incident-overview-body">
              
              <div style={{ marginBottom: '2rem' }}>
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
                    <div style={{ color: getSeverityStyle(incident.severity).color, fontWeight: 700, fontSize: '1.25rem' }}>{incident.severity}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Status</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '1.25rem' }}>{incident.status}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Attack Window</div>
                    <div style={{ color: 'var(--text-ivory)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>{attackWindow}</div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--bg-border)', paddingTop: '1.5rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '2rem' }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Affected Hosts</div>
                    <div style={{ color: 'var(--text-ivory)' }}>{affectedHosts.length > 0 ? affectedHosts.join(', ') : 'None'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>Affected Users</div>
                    <div style={{ color: 'var(--text-ivory)' }}>{affectedUsers.length > 0 ? affectedUsers.join(', ') : 'None'}</div>
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
          )}"""

content = re.sub(
    r'<\!-\- Header Info \-\->.*?</div>\s*</div>\s*\)\}\s*</div>',
    new_details_panel + '\n        </div>',
    content, flags=re.DOTALL
)

with open(path, 'w') as f:
    f.write(content)

print("Overview refactored.")
