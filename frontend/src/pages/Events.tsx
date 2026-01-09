import { useQuery } from '@tanstack/react-query'
import api from '../services/api'
import { useState } from 'react'
import './Events.css'

export default function Events() {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null)

  const { data: events, isLoading } = useQuery({
    queryKey: ['events'],
    queryFn: () => api.get('/events?limit=100').then((res) => res.data),
  })

  const { data: incidents } = useQuery({
    queryKey: ['incidents'],
    queryFn: () => api.get('/incidents').then((res) => res.data),
  })

  const { data: incidentEvents } = useQuery({
    queryKey: ['incident-events', selectedIncidentId],
    queryFn: () => api.get(`/events?incident_id=${selectedIncidentId}&limit=1000`).then((res) => res.data),
    enabled: !!selectedIncidentId,
  })

  const selectedIncident = incidents?.incidents?.find((inc: any) => inc.id === selectedIncidentId)

  return (
    <div className="events">
      <h1>Events & Incidents</h1>
      <div className="tabs">
        <div className="tab-content">
          <h2>Recent Events</h2>
          {isLoading ? (
            <p>Loading...</p>
          ) : (
            <div className="events-table">
              <table>
                <thead>
                  <tr>
                    <th>Level</th>
                    <th>Type</th>
                    <th>Honeypot</th>
                    <th>Source IP</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {events?.events && events.events.length > 0 ? events.events.map((event: any) => (
                    <tr key={event.id}>
                      <td>
                        <span className={`level-badge level-${event.level}`}>
                          {event.level}
                        </span>
                      </td>
                      <td>{event.event_type}</td>
                      <td>
                        {event.honeypot_name || event.honeypot_type ? (
                          <span>
                            {event.honeypot_name || `${event.honeypot_type?.toUpperCase() || 'Unknown'}`}
                            {event.honeypot_port && `:${event.honeypot_port}`}
                          </span>
                        ) : (
                          <span>Unknown</span>
                        )}
                      </td>
                      <td>{event.source_ip}</td>
                      <td>{new Date(event.timestamp).toLocaleString()}</td>
                    </tr>
                  )) : (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '20px' }}>
                        No events yet
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className="tab-content">
          <h2>Incidents</h2>
          <div className="incidents-list">
            {incidents?.incidents && incidents.incidents.length > 0 ? incidents.incidents.map((incident: any) => (
              <div 
                key={incident.id} 
                className={`incident-card ${selectedIncidentId === incident.id ? 'selected' : ''}`}
                onClick={() => setSelectedIncidentId(selectedIncidentId === incident.id ? null : incident.id)}
                style={{ cursor: 'pointer' }}
              >
                <div className="incident-header">
                  <span className={`level-badge level-${incident.threat_level}`}>
                    Level {incident.threat_level}
                  </span>
                  <span className="status">{incident.status}</span>
                </div>
                <p><strong>Honeypot:</strong> {incident.honeypot_name || `${incident.honeypot_type?.toUpperCase() || 'Unknown'}`}{incident.honeypot_port && `:${incident.honeypot_port}`}</p>
                <p><strong>IP:</strong> {incident.source_ip}</p>
                <p><strong>Events:</strong> {incident.event_count}</p>
                <p><strong>First seen:</strong> {new Date(incident.first_seen).toLocaleString()}</p>
                <p><strong>Last seen:</strong> {new Date(incident.last_seen).toLocaleString()}</p>
              </div>
            )) : <p>No incidents yet</p>}
          </div>
        </div>
        {selectedIncidentId && selectedIncident && (
          <div className="tab-content incident-details">
            <div className="incident-details-header">
              <h2>Incident Details</h2>
              <button onClick={() => setSelectedIncidentId(null)} className="close-btn">×</button>
            </div>
            <div className="incident-info">
              <p><strong>Honeypot:</strong> {selectedIncident.honeypot_name || `${selectedIncident.honeypot_type?.toUpperCase() || 'Unknown'}`}{selectedIncident.honeypot_port && `:${selectedIncident.honeypot_port}`}</p>
              <p><strong>Source IP:</strong> {selectedIncident.source_ip}</p>
              <p><strong>Threat Level:</strong> <span className={`level-badge level-${selectedIncident.threat_level}`}>Level {selectedIncident.threat_level}</span></p>
              <p><strong>Status:</strong> {selectedIncident.status}</p>
              <p><strong>Total Events:</strong> {selectedIncident.event_count}</p>
              <p><strong>First seen:</strong> {new Date(selectedIncident.first_seen).toLocaleString()}</p>
              <p><strong>Last seen:</strong> {new Date(selectedIncident.last_seen).toLocaleString()}</p>
            </div>
            <h3>Events Timeline</h3>
            <div className="events-timeline">
              {incidentEvents?.events && incidentEvents.events.length > 0 ? (
                incidentEvents.events.map((event: any, index: number) => (
                  <div key={event.id} className="event-detail-card">
                    <div className="event-detail-header">
                      <span className="event-number">#{index + 1}</span>
                      <span className={`level-badge level-${event.level}`}>Level {event.level}</span>
                      <span className="event-type">{event.event_type}</span>
                      <span className="event-time">{new Date(event.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="event-detail-body">
                      {(event.event_type?.startsWith('postgres') || event.details?.username || event.details?.database) ? (
                        <>
                          <div className="detail-section">
                            <strong>PostgreSQL Connection Details:</strong>
                            {event.details?.username && (
                              <div className="detail-item">
                                <span className="detail-label">Username:</span>
                                <span className="detail-value code">{event.details.username}</span>
                              </div>
                            )}
                            {event.details?.password && (
                              <div className="detail-item">
                                <span className="detail-label">Password:</span>
                                <span className="detail-value code" style={{ color: '#ff6b6b', fontWeight: 'bold' }}>{event.details.password}</span>
                              </div>
                            )}
                            {event.details?.database && (
                              <div className="detail-item">
                                <span className="detail-label">Database:</span>
                                <span className="detail-value code">{event.details.database}</span>
                              </div>
                            )}
                            {event.details?.query && (
                              <div className="detail-item">
                                <span className="detail-label">SQL Query:</span>
                                <pre className="detail-value code body-content" style={{ background: '#1e1e1e', padding: '10px', borderRadius: '4px', marginTop: '5px', color: '#d4d4d4' }}>{event.details.query}</pre>
                              </div>
                            )}
                          </div>
                          {event.details?.startup_params && Object.keys(event.details.startup_params).length > 0 && (
                            <div className="detail-section">
                              <strong>Startup Parameters:</strong>
                              <pre className="detail-value code">{JSON.stringify(event.details.startup_params, null, 2)}</pre>
                            </div>
                          )}
                          {event.details?.request_text && (
                            <div className="detail-section">
                              <strong>Raw Request Data:</strong>
                              <pre className="detail-value code body-content" style={{ background: '#1e1e1e', padding: '10px', borderRadius: '4px', fontSize: '12px', maxHeight: '200px', overflow: 'auto', color: '#d4d4d4' }}>{event.details.request_text}</pre>
                            </div>
                          )}
                        </>
                      ) : (event.event_type?.startsWith('ssh') || (event.details?.username && event.details?.command)) ? (
                        <>
                          <div className="detail-section">
                            <strong>SSH Connection Details:</strong>
                            {event.details?.username && (
                              <div className="detail-item">
                                <span className="detail-label">Username:</span>
                                <span className="detail-value code">{event.details.username}</span>
                              </div>
                            )}
                            {event.details?.password && (
                              <div className="detail-item">
                                <span className="detail-label">Password:</span>
                                <span className="detail-value code" style={{ color: '#ff6b6b', fontWeight: 'bold' }}>{event.details.password}</span>
                              </div>
                            )}
                            {event.details?.method && (
                              <div className="detail-item">
                                <span className="detail-label">Auth Method:</span>
                                <span className="detail-value code">{event.details.method}</span>
                              </div>
                            )}
                            {event.details?.command && (
                              <div className="detail-item">
                                <span className="detail-label">Command:</span>
                                <pre className="detail-value code body-content" style={{ background: '#1e1e1e', padding: '10px', borderRadius: '4px', marginTop: '5px', color: '#d4d4d4' }}>{event.details.command}</pre>
                              </div>
                            )}
                            {event.details?.local_version && (
                              <div className="detail-item">
                                <span className="detail-label">Local Version:</span>
                                <span className="detail-value code">{event.details.local_version}</span>
                              </div>
                            )}
                            {event.details?.remote_version && (
                              <div className="detail-item">
                                <span className="detail-label">Remote Version:</span>
                                <span className="detail-value code">{event.details.remote_version}</span>
                              </div>
                            )}
                          </div>
                          {event.details?.request_text && (
                            <div className="detail-section">
                              <strong>Raw Request Data:</strong>
                              <pre className="detail-value code body-content" style={{ background: '#1e1e1e', padding: '10px', borderRadius: '4px', fontSize: '12px', maxHeight: '200px', overflow: 'auto', color: '#d4d4d4' }}>{event.details.request_text}</pre>
                            </div>
                          )}
                        </>
                      ) : (
                        <>
                          <div className="detail-section">
                            <strong>Request Details:</strong>
                            <div className="detail-item">
                              <span className="detail-label">Method:</span>
                              <span className="detail-value">{event.details?.method || 'N/A'}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">Path:</span>
                              <span className="detail-value code">{event.details?.path || 'N/A'}</span>
                            </div>
                            <div className="detail-item">
                              <span className="detail-label">Full URL:</span>
                              <span className="detail-value code">{event.details?.full_url || 'N/A'}</span>
                            </div>
                            {event.details?.query && Object.keys(event.details.query).length > 0 && (
                              <div className="detail-item">
                                <span className="detail-label">Query Params:</span>
                                <pre className="detail-value code">{JSON.stringify(event.details.query, null, 2)}</pre>
                              </div>
                            )}
                          </div>
                          {event.details?.headers && (
                            <div className="detail-section">
                              <strong>Headers:</strong>
                              <pre className="detail-value code">{JSON.stringify(event.details.headers, null, 2)}</pre>
                            </div>
                          )}
                          {(event.details?.body || event.details?.body_length > 0) && (
                            <div className="detail-section">
                              <strong>Request Body:</strong>
                              {event.details.body ? (
                                <pre className="detail-value code body-content">{event.details.body}</pre>
                              ) : (
                                <pre className="detail-value code body-content">[Body exists but content not captured, length: {event.details.body_length} bytes]</pre>
                              )}
                            </div>
                          )}
                          {event.details?.cookies && Object.keys(event.details.cookies).length > 0 && (
                            <div className="detail-section">
                              <strong>Cookies:</strong>
                              <pre className="detail-value code">{JSON.stringify(event.details.cookies, null, 2)}</pre>
                            </div>
                          )}
                        </>
                      )}
                      {event.honeytoken_id && (
                        <div className="detail-section honeytoken-alert">
                          <strong>⚠️ Honeytoken Detected!</strong>
                          <p>Honeytoken ID: {event.honeytoken_id}</p>
                          {event.details?.honeytoken_username && (
                            <p>Username: <strong>{event.details.honeytoken_username}</strong></p>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <p>No events found for this incident</p>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
