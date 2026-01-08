import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../services/api'
import { useState, useEffect, useRef } from 'react'
import './Settings.css'

export default function Settings() {
  const queryClient = useQueryClient()
  const hasInitialized = useRef(false)
  
  const { data: currentSettings, isLoading } = useQuery({
    queryKey: ['notification-settings'],
    queryFn: () => api.get('/notifications/settings').then((res) => res.data),
  })

  const [localSettings, setLocalSettings] = useState<{
    telegram_enabled: boolean
    telegram_bot_token: string
    telegram_chat_id: string
    level_1_enabled: boolean
    level_2_enabled: boolean
    level_3_enabled: boolean
  }>(() => {
    const savedChanges = sessionStorage.getItem('notification-settings-draft')
    if (savedChanges) {
      try {
        return JSON.parse(savedChanges)
      } catch (e) {
      }
    }
    
    return {
      telegram_enabled: true,
      telegram_bot_token: '',
      telegram_chat_id: '',
      level_1_enabled: false,
      level_2_enabled: true,
      level_3_enabled: true,
    }
  })

  useEffect(() => {
    if (currentSettings && !isLoading && !hasInitialized.current) {
      const savedChanges = sessionStorage.getItem('notification-settings-draft')
      
      if (!savedChanges) {
        const initialSettings = {
          telegram_enabled: currentSettings.telegram_enabled ?? true,
          telegram_bot_token: currentSettings.telegram_bot_token || '',
          telegram_chat_id: currentSettings.telegram_chat_id || '',
          level_1_enabled: currentSettings.level_1_enabled ?? false,
          level_2_enabled: currentSettings.level_2_enabled ?? true,
          level_3_enabled: currentSettings.level_3_enabled ?? true,
        }
        setLocalSettings(initialSettings)
      }
      
      hasInitialized.current = true
    }
  }, [currentSettings, isLoading])

  const settings = localSettings

  const updateMutation = useMutation({
    mutationFn: (data: any) => api.put('/notifications/settings', data),
    onSuccess: (responseData) => {
      queryClient.setQueryData(['notification-settings'], responseData)
      const savedSettings = {
        telegram_enabled: responseData.telegram_enabled ?? true,
        telegram_bot_token: responseData.telegram_bot_token || '',
        telegram_chat_id: responseData.telegram_chat_id || '',
        level_1_enabled: responseData.level_1_enabled ?? false,
        level_2_enabled: responseData.level_2_enabled ?? true,
        level_3_enabled: responseData.level_3_enabled ?? true,
      }
      setLocalSettings(savedSettings)
      sessionStorage.removeItem('notification-settings-draft')
    },
    onError: (error: any) => {
      console.error('Failed to save settings:', error)
      alert(`Failed to save settings: ${error.response?.data?.detail || error.message}`)
    },
  })

  const handleSave = () => {
    updateMutation.mutate(settings)
  }

  const handleChange = (field: keyof typeof settings, value: any) => {
    const newSettings = { ...settings, [field]: value }
    setLocalSettings(newSettings)
    sessionStorage.setItem('notification-settings-draft', JSON.stringify(newSettings))
  }

  if (isLoading) {
    return <div className="settings"><p>Loading settings...</p></div>
  }

  return (
    <div className="settings">
      <h1>Settings</h1>
      <div className="settings-form">
        <h2>Notification Settings</h2>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={settings.telegram_enabled}
              onChange={(e) => handleChange('telegram_enabled', e.target.checked)}
            />
            Enable Telegram notifications
          </label>
        </div>
        <div className="form-group">
          <label>
            Telegram Bot Token:
            <input
              type="password"
              value={settings.telegram_bot_token}
              onChange={(e) => handleChange('telegram_bot_token', e.target.value)}
              placeholder="Bot token from @BotFather"
            />
          </label>
          <small style={{ color: '#666', fontSize: '12px', marginLeft: '10px' }}>
            Получите токен от @BotFather в Telegram
          </small>
        </div>
        <div className="form-group">
          <label>
            Telegram Chat ID:
            <input
              type="text"
              value={settings.telegram_chat_id}
              onChange={(e) => handleChange('telegram_chat_id', e.target.value)}
              placeholder="Your Telegram Chat ID"
            />
          </label>
          <small style={{ color: '#666', fontSize: '12px', marginLeft: '10px' }}>
            Chat ID нужен, чтобы бот знал, куда отправлять сообщения. 
            Отправьте /start вашему боту, затем получите Chat ID через @userinfobot
          </small>
        </div>
        <h3>Alert Levels</h3>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={settings.level_1_enabled}
              onChange={(e) => handleChange('level_1_enabled', e.target.checked)}
            />
            Level 1 - Port Scanning
          </label>
        </div>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={settings.level_2_enabled}
              onChange={(e) => handleChange('level_2_enabled', e.target.checked)}
            />
            Level 2 - Brute Force
          </label>
        </div>
        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={settings.level_3_enabled}
              onChange={(e) => handleChange('level_3_enabled', e.target.checked)}
            />
            Level 3 - Compromise (Critical)
          </label>
        </div>
        <button 
          onClick={handleSave} 
          className="save-btn"
          disabled={updateMutation.isPending}
        >
          {updateMutation.isPending ? 'Saving...' : 'Save Settings'}
        </button>
        {updateMutation.isSuccess && (
          <p style={{ color: 'green', marginTop: '10px' }}>✓ Settings saved!</p>
        )}
      </div>
    </div>
  )
}

