import re

path = '/Users/arnav/ZEROTRACE/frontend/src/components/InvestigationWorkspace.jsx'
with open(path, 'r') as f:
    content = f.read()

# Replace overview button
content = re.sub(
    r'<button\s*onClick=\{\(\) => handlePageChange\(\'overview\'\)\}[^>]+>.*?<span className="nav-btn-title">Overview</span>.*?</button>',
    '<button onClick={() => handlePageChange(\'overview\')} className={`sidebar-nav-btn ${activeTab === \'overview\' ? \'active\' : \'\'}`}> <span className="nav-btn-title">Overview</span> </button>',
    content, flags=re.DOTALL
)

# Replace timeline button
content = re.sub(
    r'<button\s*onClick=\{\(\) => handlePageChange\(\'timeline\'\)\}[^>]+>.*?<span className="nav-btn-title">Attack Timeline</span>.*?</button>',
    '<button onClick={() => handlePageChange(\'timeline\')} className={`sidebar-nav-btn ${activeTab === \'timeline\' ? \'active\' : \'\'}`}> <span className="nav-btn-title">Attack Timeline</span> </button>',
    content, flags=re.DOTALL
)

# Replace threat_intel button
content = re.sub(
    r'<button\s*onClick=\{\(\) => handlePageChange\(\'threat_intel\'\)\}[^>]+>.*?<span className="nav-btn-title">Threat Intel</span>.*?</button>',
    '<button onClick={() => handlePageChange(\'threat_intel\')} className={`sidebar-nav-btn ${activeTab === \'threat_intel\' ? \'active\' : \'\'}`}> <span className="nav-btn-title">Threat Intel</span> </button>',
    content, flags=re.DOTALL
)

# Replace ai_investigation button
content = re.sub(
    r'<button\s*onClick=\{\(\) => handlePageChange\(\'ai_investigation\'\)\}[^>]+>.*?<span className="nav-btn-title">AI Investigation</span>.*?</button>',
    '<button onClick={() => handlePageChange(\'ai_investigation\')} className={`sidebar-nav-btn ${activeTab === \'ai_investigation\' ? \'active\' : \'\'}`}> <span className="nav-btn-title">AI Investigation</span> </button>',
    content, flags=re.DOTALL
)

# Remove redundant header tags "CONSOLE PAGES"
content = re.sub(r'<div className="sidebar-section-header">.*?</div>', '', content, flags=re.DOTALL, count=1)

with open(path, 'w') as f:
    f.write(content)

print("Sidebar simplified.")
