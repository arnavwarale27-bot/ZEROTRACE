import re

path = '/Users/arnav/ZEROTRACE/frontend/src/components/AIInvestigationResponse.jsx'
with open(path, 'r') as f:
    content = f.read()

# 1. Remove Section 04 redundancy
content = re.sub(
    r'<div className="section-header-box">.*?</div>',
    '<div className="section-header-box" style={{ marginBottom: "2rem" }}>\n  <h2 className="section-main-heading" style={{ fontSize: "clamp(3rem, 5vw, 5rem)", fontWeight: 900, textTransform: "uppercase", letterSpacing: "-0.04em" }}>AI Investigation</h2>\n</div>',
    content, flags=re.DOTALL
)

# 2. Flatten AI Synthesis card
content = re.sub(
    r'<div className="synthesis-card">.*?</div>\s*</div>\s*</div>',
    """<div style={{ border: '1px solid var(--bg-border)', padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem', marginBottom: '2rem' }}>
      <div style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--text-ivory)' }}>Synthesis Report</div>
      <div style={{ color: 'var(--text-muted)', lineHeight: 1.6, fontSize: '0.9rem' }}>{investigationData.ai_synthesis.summary}</div>
      <div style={{ color: 'var(--text-muted)', lineHeight: 1.6, fontSize: '0.9rem' }}>{investigationData.ai_synthesis.what_happened}</div>
      <div style={{ color: 'var(--text-muted)', lineHeight: 1.6, fontSize: '0.9rem' }}>{investigationData.ai_synthesis.why_suspicious}</div>
      <div style={{ marginTop: '1rem', display: 'flex', gap: '2rem' }}>
        <div><span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', display: 'block' }}>Confidence</span><span style={{ fontSize: '1.1rem', color: 'var(--accent-amber)' }}>{Math.round(investigationData.ai_synthesis.confidence * 100)}%</span></div>
      </div>
    </div>""",
    content, flags=re.DOTALL
)

with open(path, 'w') as f:
    f.write(content)

print("AI refactored.")
