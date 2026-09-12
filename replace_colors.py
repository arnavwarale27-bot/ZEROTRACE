import re

css_path = '/Users/arnav/ZEROTRACE/frontend/src/index.css'

with open(css_path, 'r') as f:
    content = f.read()

# Define the new minimal palette
palette = {
    'bg': '#1a1917',
    'surface': 'rgba(234, 229, 217, 0.05)',
    'border': 'rgba(234, 229, 217, 0.15)',
    'text': '#eae5d9',
    'text_muted': 'rgba(234, 229, 217, 0.6)'
}

# 1. Replace the root variables directly (this is where most themes are defined)
root_vars = """
:root {
  --bg-black: #1a1917;
  --bg-card: rgba(234, 229, 217, 0.03);
  --bg-surface: rgba(234, 229, 217, 0.05);
  --bg-surface-hover: rgba(234, 229, 217, 0.08);
  --bg-border: rgba(234, 229, 217, 0.1);
  --bg-border-hover: rgba(234, 229, 217, 0.2);
  
  --primary-cyan: #eae5d9;
  --primary-cyan-glow: rgba(234, 229, 217, 0.15);
  --accent-amber: #eae5d9;
  --accent-amber-glow: rgba(234, 229, 217, 0.15);
  --accent-emerald: #eae5d9;
  --accent-rose: #eae5d9;
  
  --text-main: #eae5d9;
  --text-secondary: rgba(234, 229, 217, 0.8);
  --text-muted: rgba(234, 229, 217, 0.6);
  --text-dim: rgba(234, 229, 217, 0.4);
  --text-ivory: #eae5d9;
  
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

# Now, we need to regex all other hex codes and rgba() in the file and map them.
# We map them based on opacity. If it's a solid hex, it becomes background or text depending on its brightness (or just rely on variables).
# Wait, if we aggressively regex hex codes, we might ruin gradients that use transparent.
# It's better to replace them contextually.

# Replace background-colors hardcoded
content = re.sub(r'background-color:\s*#[0-9a-fA-F]{3,6};', 'background-color: var(--bg-black);', content)
content = re.sub(r'color:\s*#[0-9a-fA-F]{3,6};', 'color: var(--text-main);', content)

# Remove all complex gradients and replace with simple subtle surfaces
content = re.sub(r'background:\s*linear-gradient\([^)]+\);', 'background: var(--bg-surface);', content)
content = re.sub(r'background:\s*radial-gradient\([^)]+\);', 'background: transparent;', content)

# Convert all rgba that are used for borders/backgrounds to use var(--bg-border) or var(--bg-surface)
# This is tricky with simple regex. Let's instead run a function over rgba
def replace_rgba(match):
    rgba_str = match.group(0)
    # Extract alpha
    alpha_match = re.search(r'rgba\([^,]+,[^,]+,[^,]+,\s*([0-9.]+)\)', rgba_str)
    if alpha_match:
        alpha = float(alpha_match.group(1))
        # If very low alpha, it's a surface
        if alpha < 0.15:
            return 'rgba(234, 229, 217, 0.05)'
        elif alpha < 0.4:
            return 'rgba(234, 229, 217, 0.15)'
        elif alpha < 0.8:
            return 'rgba(234, 229, 217, 0.4)'
        else:
            return 'rgba(234, 229, 217, 0.9)'
    return rgba_str

content = re.sub(r'rgba\([^)]+\)', replace_rgba, content)

# Convert remaining hex codes to text or background based on a simple heuristic (just make them text)
content = re.sub(r'#[0-9a-fA-F]{6}', '#eae5d9', content)
content = re.sub(r'#[0-9a-fA-F]{3}', '#eae5d9', content)

with open(css_path, 'w') as f:
    f.write(content)

print("Styles updated")
