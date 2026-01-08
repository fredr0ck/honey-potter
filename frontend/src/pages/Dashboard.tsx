import { useQuery } from '@tanstack/react-query'
import api from '../services/api'
import './Dashboard.css'

export default function Dashboard() {
  const { data: honeypots } = useQuery({
    queryKey: ['honeypots'],
    queryFn: () => api.get('/honeypots').then((res) => res.data),
  })

  const { data: events } = useQuery({
    queryKey: ['events'],
    queryFn: () => api.get('/events?limit=10').then((res) => res.data),
  })

  const { data: incidents } = useQuery({
    queryKey: ['incidents'],
    queryFn: () => api.get('/incidents?limit=10').then((res) => res.data),
  })

  const stats = {
    honeypots: Array.isArray(honeypots) ? honeypots.length : 0,
    running: Array.isArray(honeypots) ? honeypots.filter((h: any) => h.status === 'running').length : 0,
    events: events?.total || 0,
    incidents: incidents?.total || 0,
  }

  return (
    <div className="dashboard">
      <h1>Dashboard</h1>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Honeypots</h3>
          <p className="stat-value">{stats.honeypots}</p>
        </div>
        <div className="stat-card">
          <h3>Running</h3>
          <p className="stat-value">{stats.running}</p>
        </div>
        <div className="stat-card">
          <h3>Total Events</h3>
          <p className="stat-value">{stats.events}</p>
        </div>
        <div className="stat-card">
          <h3>Active Incidents</h3>
          <p className="stat-value">{stats.incidents}</p>
        </div>
      </div>
      <div className="recent-section">
        <h2>Recent Events</h2>
        <div className="events-list">
          {events?.events && events.events.length > 0 ? events.events.map((event: any) => (
            <div key={event.id} className="event-item">
              <span className={`level-badge level-${event.level}`}>
                Level {event.level}
              </span>
              <span>{event.event_type}</span>
              <span>{event.source_ip}</span>
              <span>{new Date(event.timestamp).toLocaleString()}</span>
            </div>
          )) : <p>No events yet</p>}
        </div>
      </div>
    </div>
  )
}

