from typing import Dict, Optional
import aiohttp
from app.core.config import settings


class TelegramNotifier:
    
    def __init__(self, bot_token: Optional[str] = None):
        self.bot_token = bot_token or settings.telegram_bot_token
        if self.bot_token:
            self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        else:
            self.base_url = None
    
    async def send_message(self, chat_id: str, text: str, parse_mode: str = "Markdown") -> bool:
        if not self.bot_token or not self.base_url:
            return False
        
        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status != 200:
                        response_text = await response.text()
                        print(f"Telegram API error: {response.status} - {response_text}")
                        return False
                    return True
        except Exception as e:
            print(f"Failed to send Telegram message: {e}")
            return False
    
    async def send_alert(
        self,
        chat_id: str,
        level: int,
        event: Dict,
        incident: Optional[Dict] = None
    ) -> bool:
        event_type = event.get('event_type', 'unknown')
        details = event.get('details', {})
        
        if event_type in ('postgres_query', 'mysql_query', 'ssh_command', 'http_request'):
            if level == 2:
                emoji = "⚠️"
                level_text = "MEDIUM - Command Execution"
                description = "Command/query execution attempt"
            else:
                emoji = "🔍"
                level_text = "LOW - Command Execution"
                description = "Command/query execution"
        elif event_type in ('postgres_auth_attempt', 'mysql_auth_attempt', 'ssh_auth_attempt', 'login_attempt', 'ssh_connection'):
            if event_type == 'ssh_connection':
                emoji = "🔍"
                level_text = "LOW - SSH Connection"
                description = "SSH connection attempt"
            else:
                emoji = "⚠️"
                level_text = "MEDIUM - Brute Force"
                description = "Brute force attempt (credentials)"
        elif event_type == 'credential_reuse':
            emoji = "🚨"
            level_text = "CRITICAL - Compromise"
            description = "System compromise! Honeytoken used"
        elif level == 3:
            emoji = "🚨"
            level_text = "CRITICAL - Compromise"
            description = "System compromise!"
        elif level == 2:
            emoji = "⚠️"
            level_text = "MEDIUM - Suspicious Activity"
            description = "Suspicious activity detected"
        elif event_type in ('ssh_connection', 'ssh_version_exchange', 'ssh_kexinit', 'ssh_raw_data'):
            emoji = "🔍"
            level_text = "LOW - SSH Connection"
            description = "SSH connection activity"
        else:
            emoji = "🔍"
            level_text = "LOW - Port Scan"
            description = "Port scanning"
        
        message = f"{emoji} *{level_text}*\n\n"
        message += f"*Description:* {description}\n"
        
        honeypot_name = event.get('honeypot_name')
        honeypot_type = event.get('honeypot_type', 'unknown')
        if honeypot_name:
            message += f"*Honeypot:* `{honeypot_name}` ({honeypot_type})\n"
        else:
            message += f"*Honeypot:* `{honeypot_type}`\n"
        
        message += f"*Source IP:* `{event.get('source_ip', 'unknown')}`\n"
        message += f"*Time:* {event.get('timestamp', 'unknown')}\n"
        
        if event_type in ('postgres_auth_attempt', 'mysql_auth_attempt', 'ssh_auth_attempt', 'login_attempt'):
            username = details.get('username', 'unknown')
            password = details.get('password', 'N/A')
            message += f"\n*Credentials used:*\n"
            message += f"Username: `{username}`\n"
            message += f"Password: `{password}`\n"
        
        if event_type in ('postgres_query', 'mysql_query'):
            query = details.get('query', details.get('parse_query', details.get('execute_query')))
            if query:
                query_preview = query[:200] + "..." if len(query) > 200 else query
                message += f"\n*SQL Query:*\n```\n{query_preview}\n```\n"
        elif event_type == 'ssh_command':
            command = details.get('command', 'N/A')
            username = details.get('username', 'unknown')
            message += f"\n*SSH Command:*\n"
            message += f"Username: `{username}`\n"
            message += f"Command: ```\n{command}\n```\n"
        elif event_type == 'ssh_connection':
            username = details.get('username', 'unknown')
            method = details.get('method', 'N/A')
            message += f"\n*Connection attempt:*\n"
            message += f"Username: `{username}`\n"
            message += f"Method: `{method}`\n"
        elif event_type == 'http_request':
            method = details.get('method', 'N/A')
            path = details.get('path', 'N/A')
            message += f"\n*Request:* `{method} {path}`\n"
        
        if incident:
            message += f"\n*Incident:* #{incident.get('id', 'unknown')[:8]}\n"
            message += f"*Events in incident:* {incident.get('event_count', 0)}\n"
        
        if level == 3 or event_type == 'credential_reuse':
            message += f"\n⚠️ *CRITICAL!*\n"
            honeytoken_username = event.get('honeytoken_username')
            if honeytoken_username:
                message += f"Honeytoken used: `{honeytoken_username}`\n"
            message += f"\nThis means attackers have already breached the server!\n"
            message += f"Urgently check the system!"
        
        return await self.send_message(chat_id, message)
