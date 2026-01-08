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
        level_info = {
            1: ("🔍", "LOW - Port Scan", "Port scanning"),
            2: ("⚠️", "MEDIUM - Brute Force", "Brute force attempt"),
            3: ("🚨", "CRITICAL - Compromise", "System compromise!")
        }
        
        emoji, level_text, description = level_info.get(level, ("📢", "Unknown", "Unknown event"))
        
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
        
        if incident:
            message += f"\n*Incident:* #{incident.get('id', 'unknown')[:8]}\n"
            message += f"*Events in incident:* {incident.get('event_count', 0)}\n"
        
        if level == 3:
            message += f"\n⚠️ *CRITICAL!*\n"
            message += f"Honeytoken used: `{event.get('honeytoken_username', 'unknown')}`\n"
            message += f"\nThis means attackers have already breached the server!\n"
            message += f"Urgently check the system!"
        
        return await self.send_message(chat_id, message)
