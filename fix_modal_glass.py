import re

path = '/Users/arnav/ZEROTRACE/frontend/src/index.css'
with open(path, 'r') as f:
    content = f.read()

# Fix overlay
overlay_regex = r'\.log-modal-overlay\s*\{[^}]+\}'
overlay_new = """.log-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  animation: pageFadeIn 0.25s ease;
}"""
content = re.sub(overlay_regex, overlay_new, content)

# Fix modal card
card_regex = r'\.log-modal-card\s*\{[^}]+\}'
card_new = """.log-modal-card {
  background: rgba(26, 26, 26, 0.75);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(243, 237, 226, 0.18);
  border-radius: 0;
  width: 100%;
  max-width: 740px;
  padding: 2rem;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}"""
content = re.sub(card_regex, card_new, content)

with open(path, 'w') as f:
    f.write(content)

print("Modal styles fixed with glass effect.")
