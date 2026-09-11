import React from 'react';

export default function LandingPage({ onStartInvestigation }) {
  return (
    <div className="fullscreen-bg-landing">
      {/* Light subtle overlay so artwork on the right remains clear */}
      <div className="fullscreen-overlay-minimal-left"></div>
      
      <div className="left-aligned-content-wrapper">
        <div className="left-hero-panel">
          
          <h1 className="brand-title-minimal">ZEROTRACE</h1>
          
          <p className="tagline-minimal">
            Turn security alerts into clear, evidence-backed incidents.
          </p>

          <div className="cta-wrapper">
            <button 
              onClick={onStartInvestigation} 
              className="start-investigation-btn-minimal"
            >
              <span>Start Investigation</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M5 12h14M12 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}
