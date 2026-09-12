import re

path = '/Users/arnav/ZEROTRACE/frontend/src/components/AttackInvestigation.jsx'
with open(path, 'r') as f:
    content = f.read()

# 1. Remove Section 02 redundancy
content = re.sub(
    r'<div className="section-header-box">.*?</div>',
    '<div className="section-header-box" style={{ marginBottom: "2rem" }}>\n  <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em" }}>Attack Timeline</h2>\n</div>',
    content, flags=re.DOTALL
)

# 2. Flatten the timeline nodes (remove heavy boxes)
new_node = """
                <div key={item.id || idx} style={{ borderBottom: '1px solid var(--bg-border)', padding: '1.5rem 0', display: 'flex', gap: '1.5rem', flexDirection: 'column' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }} onClick={() => handleToggleEvent(item.source_event_id)} style={{ cursor: 'pointer' }}>
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
"""

content = re.sub(
    r'<div key=\{item.id.*?</div>\s*</div>\s*</div>',
    new_node,
    content, flags=re.DOTALL
)

# Fix a small bug in the JSX (two style props on the onClick div)
content = content.replace("style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }} onClick={() => handleToggleEvent(item.source_event_id)} style={{ cursor: 'pointer' }}",
                          "style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', cursor: 'pointer' }} onClick={() => handleToggleEvent(item.source_event_id)}")

with open(path, 'w') as f:
    f.write(content)

print("Timeline refactored.")
