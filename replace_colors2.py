import re

css_path = '/Users/arnav/ZEROTRACE/frontend/src/index.css'

with open(css_path, 'r') as f:
    content = f.read()

# Define the new minimal palette
palette = {
    'bg': '#22211F',
    'surface': 'rgba(234, 229, 217, 0.05)',
    'border': 'rgba(234, 229, 217, 0.15)',
    'text': '#EAE5D9',
}

root_vars = """
:root {
  --bg-black: #22211F;
  --bg-card: rgba(234, 229, 217, 0.05);
  --bg-surface: rgba(234, 229, 217, 0.08);
  --bg-surface-hover: rgba(234, 229, 217, 0.12);
  --bg-border: rgba(234, 229, 217, 0.15);
  --bg-border-hover: rgba(234, 229, 217, 0.25);
  
  --primary-cyan: #EAE5D9;
  --primary-cyan-glow: rgba(234, 229, 217, 0.15);
  --accent-amber: #EAE5D9;
  --accent-amber-glow: rgba(234, 229, 217, 0.15);
  --accent-emerald: #EAE5D9;
  --accent-rose: #EAE5D9;
  
  --text-main: #EAE5D9;
  --text-secondary: rgba(234, 229, 217, 0.8);
  --text-muted: rgba(234, 229, 217, 0.5);
  --text-dim: rgba(234, 229, 217, 0.3);
  --text-ivory: #EAE5D9;
  
  /* Inter Specimen Typography System */
  --font-inter: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-inter-tight: 'Inter Tight', 'Inter', sans-serif;
  --font-brand-title: 'Inter Tight', 'Inter', -apple-system, sans-serif;
  --font-tagline: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-btn: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}
"""

content = re.sub(r':root\s*\{.*?\n\}', root_vars, content, flags=re.DOTALL)

# Replace all background hex colors except for black and transparent
def hex_replacer(match):
    full_str = match.group(0)
    hex_val = match.group(1).lower()
    if hex_val in ['000', '000000']:
        return full_str # Keep shadows black
    return full_str.replace(f'#{match.group(1)}', '#EAE5D9')

content = re.sub(r'color:\s*#([0-9a-fA-F]{3,6});', hex_replacer, content)

# To force background colors without breaking complex properties
content = re.sub(r'background-color:\s*#([0-9a-fA-F]{3,6});', r'background-color: var(--bg-black);', content)

# Remove all complex gradients 
content = re.sub(r'background:\s*linear-gradient\([^;]+;', 'background: var(--bg-surface);', content)
content = re.sub(r'background:\s*radial-gradient\([^;]+;', 'background: transparent;', content)

# We also need to fix `.brand-title-minimal` font size from `clamp(4.8rem, 8vw, 7.2rem)` to much larger
content = content.replace('font-size: clamp(4.8rem, 8vw, 7.2rem);', 'font-size: clamp(8rem, 15vw, 14rem);')

with open(css_path, 'w') as f:
    f.write(content)

print("Styles updated")
