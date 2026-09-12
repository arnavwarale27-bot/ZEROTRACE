import re

with open('/Users/arnav/ZEROTRACE/frontend/src/index.css', 'r') as f:
    css = f.read()

# 1. Update :root
root_vars = """:root {
  --bg-black: #1a1a1a;
  --bg-card: transparent;
  --bg-surface: transparent;
  --bg-surface-hover: rgba(240, 236, 227, 0.05);
  --bg-border: rgba(240, 236, 227, 0.15);
  --bg-border-hover: rgba(240, 236, 227, 0.4);
  
  --primary-cyan: #fbbf24;
  --primary-cyan-glow: rgba(251, 191, 36, 0.15);
  --accent-amber: #fbbf24;
  --accent-amber-glow: rgba(251, 191, 36, 0.15);
  --accent-emerald: #fbbf24;
  --accent-rose: #fbbf24;
  
  --text-main: #f0ece3;
  --text-secondary: rgba(240, 236, 227, 0.7);
  --text-muted: rgba(240, 236, 227, 0.4);
  --text-dim: rgba(240, 236, 227, 0.2);
  --text-ivory: #f0ece3;
  
  --font-inter: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-inter-tight: 'Inter Tight', 'Inter', sans-serif;
  --font-brand-title: 'Inter Tight', 'Inter', -apple-system, sans-serif;
  --font-tagline: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-btn: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}"""
css = re.sub(r':root\s*\{.*?\n\}', root_vars, css, flags=re.DOTALL)

# Also override .console-ambient-canvas overrides
css = re.sub(
    r'\.console-ambient-canvas\s*\{[^}]+\}',
    '.console-ambient-canvas {\n  min-height: 100vh;\n  width: 100vw;\n  background-color: var(--bg-black);\n  position: relative;\n  overflow-x: hidden;\n  padding: 4rem 2rem;\n  display: flex;\n  flex-direction: column;\n  align-items: center;\n}',
    css, flags=re.DOTALL
)

# 2. Update Typography for landing page
css = re.sub(
    r'\.brand-title-minimal\s*\{[^}]+\}',
    '.brand-title-minimal {\n  font-family: var(--font-brand-title);\n  font-size: clamp(8rem, 15vw, 16rem);\n  font-weight: 900;\n  letter-spacing: -0.05em;\n  line-height: 0.85;\n  text-transform: uppercase;\n  color: var(--text-ivory);\n}',
    css
)

# 3. Update Button (Landing Page)
css = re.sub(
    r'\.start-investigation-btn-minimal\s*\{[^}]+\}',
    '.start-investigation-btn-minimal {\n  display: inline-flex;\n  align-items: center;\n  gap: 1rem;\n  padding: 1rem 2rem;\n  font-family: var(--font-btn);\n  font-size: 0.85rem;\n  font-weight: 600;\n  letter-spacing: 0.1em;\n  text-transform: uppercase;\n  color: var(--text-ivory);\n  background: transparent;\n  border: 1px solid var(--text-ivory);\n  border-radius: 0;\n  cursor: pointer;\n  transition: all 0.2s;\n  text-decoration: none;\n}',
    css
)
css = re.sub(
    r'\.start-investigation-btn-minimal:hover\s*\{[^}]+\}',
    '.start-investigation-btn-minimal:hover {\n  background: var(--text-ivory);\n  color: var(--bg-black);\n}',
    css
)
css = re.sub(
    r'\.start-investigation-btn-minimal:active\s*\{[^}]+\}',
    '.start-investigation-btn-minimal:active {\n  opacity: 0.8;\n}',
    css
)

# 4. Remove heavy box shadows and backgrounds from typical card classes
# Let's find common patterns like `background: rgba(18, 24, 38...` or `box-shadow:` and neuter them.
css = re.sub(r'box-shadow:[^;]+;', 'box-shadow: none;', css)
css = re.sub(r'border-radius:\s*[1-9][0-9]*px;', 'border-radius: 0;', css)
css = re.sub(r'border-radius:\s*0\.5rem;', 'border-radius: 0;', css)

# Make all cards flat 1px border
css = re.sub(r'background:\s*rgba\([^)]+\);', 'background: transparent;', css)
css = re.sub(r'backdrop-filter:[^;]+;', 'backdrop-filter: none;', css)

with open('/Users/arnav/ZEROTRACE/frontend/src/index.css', 'w') as f:
    f.write(css)

print("CSS rewritten.")
