export interface User {
  id: string
  username: string
  email?: string
  is_active: boolean
  created_at: string
}

export interface Honeypot {
  id: string
  type: string
  port: number
  address: string
  status: string
  config: Record<string, any>
  docker_container_id?: string
  notification_levels: Record<string, boolean>
  created_at: string
  updated_at?: string
}

export interface Credential {
  id: string
  service_id?: string
  service_type: string
  username: string
  password: string
  generated_at: string
  used_at?: string
  meta_data?: string
}

export interface Event {
  id: string
  honeypot_id: string
  incident_id?: string
  event_type: string
  level: number
  source_ip: string
  honeytoken_id?: string
  timestamp: string
  details: Record<string, any>
}

export interface Incident {
  id: string
  honeypot_id: string
  source_ip: string
  threat_level: number
  status: string
  event_count: number
  first_seen: string
  last_seen: string
  details: Record<string, any>
}

export interface NotificationSettings {
  id: string
  user_id: string
  telegram_enabled: boolean
  telegram_chat_id?: string
  email_enabled: boolean
  email_address?: string
  level_1_enabled: boolean
  level_2_enabled: boolean
  level_3_enabled: boolean
}

