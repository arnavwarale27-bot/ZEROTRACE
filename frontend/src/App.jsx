import React, { useState } from 'react';
import LandingPage from './components/LandingPage';
import InvestigationWorkspace from './components/InvestigationWorkspace';

export default function App() {
  const [currentView, setCurrentView] = useState('landing'); // 'landing' | 'workspace'

  return (
    <>
      {currentView === 'landing' ? (
        <LandingPage onStartInvestigation={() => setCurrentView('workspace')} />
      ) : (
        <InvestigationWorkspace onBackToLanding={() => setCurrentView('landing')} />
      )}
    </>
  );
}
