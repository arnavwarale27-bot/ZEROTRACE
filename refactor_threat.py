import re

path = '/Users/arnav/ZEROTRACE/frontend/src/components/ThreatIntelligence.jsx'
with open(path, 'r') as f:
    content = f.read()

# 1. Remove Section 03 redundancy
content = re.sub(
    r'<div className="section-header-box">.*?</div>',
    '<div className="section-header-box" style={{ marginBottom: "2rem" }}>\n  <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em" }}>Threat Intelligence</h2>\n</div>',
    content, flags=re.DOTALL
)

# 2. Refactor IOC cards
content = re.sub(
    r'<div key=\{idx\} className="ioc-card">.*?</div>\s*</div>\s*</div>',
    """<div key={idx} style={{ padding: '1.5rem', border: '1px solid var(--bg-border)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{ioc.ioc_type}</div>
      <div style={{ fontSize: '1.1rem', color: 'var(--text-ivory)', fontFamily: 'var(--font-mono)' }}>{ioc.ioc_value}</div>
      <div style={{ fontSize: '0.8rem', color: ioc.reputation === 'malicious' ? '#fbbf24' : 'var(--text-muted)' }}>{ioc.reputation.toUpperCase()} - {ioc.provider}</div>
    </div>""",
    content, flags=re.DOTALL
)

# 3. Refactor MITRE cards
content = re.sub(
    r'<div key=\{idx\} className="mitre-card">.*?</div>\s*</div>\s*</div>',
    """<div key={idx} style={{ padding: '1.5rem', border: '1px solid var(--bg-border)', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase' }}>{mitre.tactic}</div>
      <div style={{ fontSize: '1.1rem', color: 'var(--text-ivory)', fontWeight: 600 }}>{mitre.technique_id} - {mitre.technique_name}</div>
      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{mitre.status.toUpperCase()}</div>
    </div>""",
    content, flags=re.DOTALL
)

with open(path, 'w') as f:
    f.write(content)

print("ThreatIntel refactored.")
