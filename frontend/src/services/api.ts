import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: `${API_URL}/api`,
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      const url = error.config?.url || ''
      
      if (!url.includes('/auth/me') && !url.includes('/auth/login')) {
        const isTokenCheck = error.config?.headers?.Authorization && url.includes('/auth/')
        
        if (!isTokenCheck) {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          if (window.location.pathname !== '/login') {
            window.location.href = '/login'
          }
        }
      }
    }
    return Promise.reject(error)
  }
)

export default api
