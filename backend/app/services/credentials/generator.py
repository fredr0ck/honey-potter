import uuid
import secrets
from typing import Dict, Optional


class CredentialGenerator:
    
    def __init__(self, prefix: str = "honey_pot"):
        self.prefix = prefix
    
    def generate_username(self, service_type: str) -> str:
        unique_id = str(uuid.uuid4()).replace('-', '')[:12]
        return f"{self.prefix}_{service_type}_{unique_id}"
    
    def generate_password(self, length: int = 32) -> str:
        return f"hp_{secrets.token_hex(length // 2)}"
    
    def generate_pair(self, service_type: str) -> Dict[str, str]:
        return {
            'username': self.generate_username(service_type),
            'password': self.generate_password(),
            'service_type': service_type
        }
    
    def generate_multiple(
        self, 
        service_type: str, 
        count: int,
        items: Optional[list[Dict[str, str]]] = None
    ) -> list[Dict[str, str]]:
        if items:
            result = []
            for item in items:
                username = item.get('username')
                meta_data = item.get('meta_data')
                
                if not username:
                    username = self.generate_username(service_type)
                
                result.append({
                    'username': username,
                    'password': self.generate_password(),
                    'service_type': service_type,
                    'meta_data': meta_data
                })
            return result
        else:
            return [self.generate_pair(service_type) for _ in range(count)]
