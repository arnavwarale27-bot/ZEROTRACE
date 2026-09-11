const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function fetchHealthStatus() {
  const startTime = performance.now();
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const latency = Math.round(performance.now() - startTime);
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const data = await response.json();
    return {
      connected: true,
      status: data.status,
      version: data.version,
      app: data.app,
      latencyMs: latency,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    const latency = Math.round(performance.now() - startTime);
    return {
      connected: false,
      error: error.message || 'Failed to connect to backend service',
      latencyMs: latency,
      timestamp: new Date().toISOString(),
    };
  }
}

export async function fetchIncidents() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/incidents`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to fetch incidents: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('fetchIncidents error:', error);
    throw error;
  }
}

export async function fetchIncidentById(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to fetch incident ${incidentId}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('fetchIncidentById error:', error);
    throw error;
  }
}

export async function fetchIncidentTimeline(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/timeline`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to fetch timeline: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('fetchIncidentTimeline error:', error);
    throw error;
  }
}

export async function fetchEventById(eventId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/events/${eventId}`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to fetch event ${eventId}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('fetchEventById error:', error);
    throw error;
  }
}

export async function fetchIncidentMitre(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/mitre`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to fetch MITRE mappings: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('fetchIncidentMitre error:', error);
    throw error;
  }
}

export async function runAIInvestigation(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/investigate`, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to run AI investigation: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('runAIInvestigation error:', error);
    throw error;
  }
}

export async function fetchInvestigation(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/investigation`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    console.warn('fetchInvestigation warning:', error);
    return null;
  }
}

export async function fetchIOCs() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/iocs`, {
      headers: { 'Accept': 'application/json' },
    });
    if (!response.ok) throw new Error(`Failed to fetch IOCs: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('fetchIOCs error:', error);
    throw error;
  }
}

export async function triggerCorrelation(timeWindowMinutes = 60) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/correlation/run`, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ time_window_minutes: timeWindowMinutes }),
    });
    if (!response.ok) throw new Error(`Failed to run correlation: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('triggerCorrelation error:', error);
    throw error;
  }
}

export async function ingestSampleBatch(logs) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/v1/events/ingest/batch`, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(logs),
    });
    if (!response.ok) throw new Error(`Failed to ingest logs: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('ingestSampleBatch error:', error);
    throw error;
  }
}
