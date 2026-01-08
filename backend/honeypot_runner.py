#!/usr/bin/env python3
import os
import sys
from flask import Flask, request, jsonify
import requests
import json

SERVICE_ID = os.getenv('SERVICE_ID', 'unknown')
PORT = int(os.getenv('PORT', '8080'))
HOST = os.getenv('HOST', '0.0.0.0')
API_URL = os.getenv('API_URL', 'http://172.17.0.1:8000')
SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')

app = Flask(__name__)

def send_event_to_backend(event_data):
    try:
        token = SECRET_KEY[:16]
        api_urls = [
            API_URL,
            "http://host.docker.internal:8000",
            "http://172.17.0.1:8000",
            "http://172.19.0.1:8000",
        ]
        
        for api_url in api_urls:
            try:
                response = requests.post(
                    f"{api_url}/api/events/internal",
                    json=event_data,
                    headers={"X-Honeypot-Token": token},
                    timeout=2
                )
                if response.status_code == 200:
                    return True
            except Exception:
                continue
    except Exception as e:
        print(f"[HONEYPOT] Failed to send event: {e}")
    return False

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def handle_request(path):
    source_ip = request.remote_addr or request.headers.get('X-Forwarded-For', 'unknown')
    if ',' in source_ip:
        source_ip = source_ip.split(',')[0].strip()
    
    body_data = ''
    try:
        if request.method in ['POST', 'PUT', 'PATCH']:
            if request.content_type and 'application/json' in request.content_type:
                body_json = request.get_json(silent=True, force=True)
                if body_json:
                    body_data = json.dumps(body_json, ensure_ascii=False)
                else:
                    body_data = request.get_data(as_text=True)
            else:
                body_data = request.get_data(as_text=True)
            
            if not body_data:
                body_data = request.form.to_dict() if request.form else ''
                if body_data:
                    body_data = json.dumps(body_data, ensure_ascii=False)
    except Exception as e:
        print(f"[HONEYPOT] Error reading body: {e}")
        import traceback
        traceback.print_exc()
        try:
            body_data = request.get_data(as_text=True)
        except Exception:
            body_data = ''
    
    query_string = request.query_string.decode('utf-8') if request.query_string else ''
    query_params = dict(request.args)
    
    try:
        host = request.headers.get('Host', None)
        if not host:
            host = request.environ.get('HTTP_HOST', None)
        if not host:
            host = request.environ.get('SERVER_NAME', 'unknown')
            port = request.environ.get('SERVER_PORT', '')
            if port and port not in ['80', '443']:
                host = f"{host}:{port}"
        
        scheme = 'https' if request.is_secure else 'http'
        if not hasattr(request, 'is_secure'):
            scheme = request.environ.get('wsgi.url_scheme', 'http')
        
        path = request.path if request.path else '/'
        full_url = f"{scheme}://{host}{path}"
        if query_string:
            full_url += f"?{query_string}"
        
        if full_url == 'http://unknown/' or full_url.startswith('http://unknown'):
            print(f"[HONEYPOT] Warning: Could not determine full URL, using fallback")
            print(f"[HONEYPOT] Headers: {list(request.headers.keys())}")
            print(f"[HONEYPOT] Environ keys: {list(request.environ.keys())[:10]}")
    except Exception as e:
        print(f"[HONEYPOT] Error building full_url: {e}")
        import traceback
        traceback.print_exc()
        host = request.headers.get('Host', 'unknown')
        path = request.path if request.path else '/'
        full_url = f"http://{host}{path}"
        if query_string:
            full_url += f"?{query_string}"
    
    all_headers = dict(request.headers)
    
    query_params_str = json.dumps(query_params, ensure_ascii=False) if query_params else ''
    request_text = f"{full_url}\n{request.path}\n{query_string}\n{query_params_str}\n{json.dumps(all_headers, ensure_ascii=False)}\n{body_data}"
    
    event_data = {
        'honeypot_id': SERVICE_ID,
        'event_type': 'http_connection',
        'level': 1,
        'source_ip': source_ip,
        'details': {
            'method': request.method,
            'path': request.path,
            'query': query_params,
            'query_string': query_string,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'headers': all_headers,
            'body': body_data[:10000] if body_data else None,
            'body_length': len(body_data) if body_data else 0,
            'content_type': request.content_type,
            'cookies': dict(request.cookies),
            'full_url': full_url,
            'request_text': request_text
        },
        'honeytoken_check': None
    }
    
    send_event_to_backend(event_data)
    
    search_query = query_params.get('q', '')
    response_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: sans-serif; margin: 20px; background-color: #f0f2f5; color: #333; }}
            .container {{ background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 800px; margin: auto; }}
            h1 {{ color: #0056b3; }}
            .search-form {{ margin-bottom: 20px; }}
            .search-input {{ width: 70%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }}
            .search-button {{ padding: 10px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }}
            .results {{ border-top: 1px solid #eee; padding-top: 20px; }}
            .result-item {{ margin-bottom: 15px; padding: 10px; background-color: #e9ecef; border-radius: 4px; }}
            .result-title {{ font-weight: bold; color: #007bff; }}
            .result-url {{ font-size: 0.9em; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Search Engine</h1>
            <div class="search-form">
                <form action="/" method="GET">
                    <input type="text" name="q" class="search-input" placeholder="Search..." value="{search_query}">
                    <button type="submit" class="search-button">Search</button>
                </form>
            </div>
            <div class="results">
                <h2>Results for "{search_query or 'nothing'}"</h2>
                <p>No results found for your query.</p>
                <div class="result-item">
                    <div class="result-title">Example Result 1</div>
                    <div class="result-url">http://example.com/page1</div>
                    <p>This is a simulated search result. Your query was: {search_query or 'N/A'}</p>
                </div>
                <div class="result-item">
                    <div class="result-title">Example Result 2</div>
                    <div class="result-url">http://example.com/page2</div>
                    <p>Another simulated result for your query.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return response_html, 200, {'Content-Type': 'text/html'}

if __name__ == '__main__':
    print(f"[HONEYPOT] Starting Flask HTTP Honeypot on {HOST}:{PORT}")
    print(f"[HONEYPOT] Service ID: {SERVICE_ID}")
    print(f"[HONEYPOT] API URL: {API_URL}")
    app.run(host=HOST, port=PORT, debug=False)
