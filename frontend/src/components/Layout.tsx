import { Outlet, Link, useLocation } from 'react-router-dom'
import { useAuth } from '../services/auth'
import './Layout.css'

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()

  const navItems = [
    { path: '/', label: 'Dashboard' },
    { path: '/honeypots', label: 'Honeypots' },
    { path: '/credentials', label: 'Honeytokens' },
    { path: '/events', label: 'Events and Incidents' },
    { path: '/settings', label: 'Settings' },
  ]

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="sidebar-header">
          <h1>🍯 Honey Potter</h1>
        </div>
        <ul className="nav-list">
          {navItems.map((item) => (
            <li key={item.path}>
              <Link
                to={item.path}
                className={location.pathname === item.path ? 'active' : ''}
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
        <div className="sidebar-footer">
          <div className="user-info">
            <span>{user?.username}</span>
          </div>
          <a
            href={`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            className="docs-btn"
          >
            📚 Documentation
          </a>
          <button onClick={logout} className="logout-btn">
            Logout
          </button>
        </div>
      </nav>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}

