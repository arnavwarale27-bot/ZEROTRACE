import re
import os

css_path = '/Users/arnav/ZEROTRACE/frontend/src/index.css'
with open(css_path, 'r') as f:
    content = f.read()

# Split the CSS file to preserve landing page
split_marker = '/* ==========================================================================\n   MAIN SOC INVESTIGATION WORKSPACE'
parts = content.split(split_marker)

if len(parts) == 2:
    landing_css = parts[0]
    workspace_css = split_marker + parts[1]
    
    # 1. Update the :root if needed, but let's just redefine inside .console-ambient-canvas
    workspace_css = re.sub(
        r'\.console-ambient-canvas\s*\{',
        '.console-ambient-canvas {\n  --primary-cyan: #eae5d9;\n  --accent-amber: #eae5d9;\n  --accent-emerald: #eae5d9;\n  --accent-rose: #eae5d9;\n  --bg-border: rgba(234, 229, 217, 0.15);\n  --bg-surface: rgba(234, 229, 217, 0.05);\n',
        workspace_css
    )
    
    # 2. Fix the ambient glows (remove blue gradients)
    workspace_css = re.sub(r'radial-gradient\(circle,\s*rgba\([^)]+\)\s*0%,\s*rgba\([^)]+\)\s*45%,\s*transparent\s*70%\)', 'transparent', workspace_css)
    workspace_css = re.sub(r'radial-gradient\(circle,\s*rgba\([^)]+\)\s*0%,\s*rgba\([^)]+\)\s*50%,\s*transparent\s*70%\)', 'transparent', workspace_css)
    
    # 3. Floating frame glass effect
    workspace_css = workspace_css.replace(
        'background: rgba(12, 16, 26, 0.94);',
        'background: #1c1b1a;\n  backdrop-filter: blur(40px);'
    )
    
    # 4. Remove all hardcoded blue/green/red hexes in workspace
    # Instead of regex hexes, I'll replace specific known ones:
    # #3b82f6 (blue), #06b6d4 (cyan), #10b981 (emerald), #f43f5e (rose), #fbbf24 (amber), #f1f5f9 (slate)
    workspace_css = re.sub(r'#(3b82f6|06b6d4|10b981|f43f5e|fbbf24|f1f5f9|60a5fa|93c5fd|34d399|64748b|94a3b8|cbd5e1)', '#eae5d9', workspace_css)
    
    # 5. Increase workspace title size
    workspace_css = workspace_css.replace(
        '.brand-name {\n  font-family: var(--font-brand-title);\n  font-weight: 700;\n  color: #fff;\n  letter-spacing: -0.02em;\n}',
        '.brand-name {\n  font-family: var(--font-brand-title);\n  font-weight: 900;\n  color: #eae5d9;\n  letter-spacing: -0.03em;\n  font-size: 1.8rem;\n}'
    )
    
    # 6. Button text visibility
    # For buttons that have an ivory background, text must be dark
    # Let's find any button with background #eae5d9 and ensure color is dark
    workspace_css = re.sub(r'background:\s*(var\(--text-ivory\)|#eae5d9);(\s*)color:\s*#eae5d9;', r'background: \1;\2color: #121316;', workspace_css)
    workspace_css = re.sub(r'background:\s*(var\(--text-ivory\)|#eae5d9);(\s*)color:\s*#[a-fA-F0-9]{3,6};', r'background: \1;\2color: #121316;', workspace_css)
    
    with open(css_path, 'w') as f:
        f.write(landing_css + workspace_css)
    print("CSS updated carefully.")
else:
    print("Failed to split CSS.")

