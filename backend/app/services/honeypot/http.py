import asyncio
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from typing import Dict
import base64
from app.services.honeypot.base import BaseHoneypot


class HTTPHoneypot(BaseHoneypot):
    
    def __init__(self, service_id: str, port: int, config: Dict):
        super().__init__(service_id, port, config)
        self.app = None
        self.runner = None
        self.site = None
        self.host = config.get('host', '0.0.0.0')
        
    async def start(self):
        self.app = web.Application()
        
        self.app.middlewares.append(self._log_middleware)
        
        self.app.router.add_route('*', '/{path:.*}', self._handle_request)
        
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        self.site = web.TCPSite(self.runner, '0.0.0.0', self.port)
        await self.site.start()
        
        self.is_running = True
        print(f"HTTP Honeypot started on 0.0.0.0:{self.port} (accessible from host)")
    
    async def stop(self):
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        self.is_running = False
        print(f"HTTP Honeypot stopped on port {self.port}")
    
    @web.middleware
    async def _log_middleware(self, request: Request, handler):
        source_ip = request.remote or request.headers.get('X-Forwarded-For', 'unknown')
        if ',' in source_ip:
            source_ip = source_ip.split(',')[0].strip()
        
        await self.log_event('http_connection', source_ip, {
            'level': 1,
            'method': request.method,
            'path': str(request.url.path),
            'query': dict(request.query),
            'user_agent': request.headers.get('User-Agent', 'unknown')
        })
        
        auth_header = request.headers.get('Authorization', '')
        if auth_header:
            await self._check_auth_header(auth_header, source_ip)
        
        response = await handler(request)
        return response
    
    async def _check_auth_header(self, auth_header: str, source_ip: str):
        if auth_header.startswith('Basic '):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    is_fake, cred_id = await self.check_credentials(
                        username, password, source_ip
                    )
                    if is_fake:
                        pass
            except Exception as e:
                await self.log_event('http_auth_attempt', source_ip, {
                    'level': 2,
                    'auth_header': auth_header[:50],
                    'error': str(e)
                })
    
    async def _handle_request(self, request: Request) -> Response:
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Welcome</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Welcome</h1>
            <p>Server is running.</p>
        </body>
        </html>
        """
        
        return web.Response(
            text=html_content,
            content_type='text/html',
            status=200
        )
    
    async def handle_connection(self, reader, writer):
        pass
