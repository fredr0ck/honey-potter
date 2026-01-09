import uuid
import secrets
import random
import string
from typing import Dict, Optional


class CredentialGenerator:
    
    def __init__(self, prefix: str = "honey_pot"):
        self.prefix = prefix
    
    def generate_username(self, service_type: str) -> str:
        username_patterns = [
            lambda: f"user{random.randint(1000, 9999)}",
            lambda: f"admin{random.randint(100, 999)}",
            lambda: f"test{random.randint(100, 999)}",
            lambda: f"guest{random.randint(10, 99)}",
            lambda: f"service{random.randint(100, 999)}",
            lambda: f"app{random.randint(1000, 9999)}",
            lambda: f"db{random.randint(100, 999)}",
            lambda: f"web{random.randint(100, 999)}",
            lambda: f"api{random.randint(1000, 9999)}",
            lambda: f"dev{random.randint(100, 999)}",
            lambda: ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 8))) + str(random.randint(10, 999)),
            lambda: ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 10))),
        ]
        return random.choice(username_patterns)()
    
    def generate_password(self, length: int = 32) -> str:
        password_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        return ''.join(secrets.choice(password_chars) for _ in range(length))
    
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
