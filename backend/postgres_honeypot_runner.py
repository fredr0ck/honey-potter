#!/usr/bin/env python3
import os
import sys
import socket
import struct
import json
import requests
import asyncio
from typing import Optional, Dict

SERVICE_ID = os.getenv('SERVICE_ID', 'unknown')
PORT = int(os.getenv('PORT', '5432'))
HOST = os.getenv('HOST', '0.0.0.0')
API_URL = os.getenv('API_URL', 'http://172.17.0.1:8000')
SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')

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
        print(f"[POSTGRES-HONEYPOT] Failed to send event: {e}")
    return False

def parse_startup_message(data: bytes) -> Dict:
    if len(data) < 8:
        return {}
    
    length = struct.unpack('!I', data[:4])[0]
    if length < 8 or len(data) < length:
        return {}
    
    proto = struct.unpack('!I', data[4:8])[0]
    if proto == 80877102:
        return {}
    
    payload = data[8:length]
    params = {}
    
    try:
        parts = payload.split(b'\x00')
        if parts and parts[-1] == b'':
            parts = parts[:-1]
        for i in range(0, len(parts) - 1, 2):
            k = parts[i].decode('utf-8', errors='replace')
            v = parts[i + 1].decode('utf-8', errors='replace') if i + 1 < len(parts) else ''
            if k:
                params[k] = v
    except Exception:
        pass
    
    return params

def parse_query_message(data: bytes) -> Optional[str]:
    if len(data) < 5:
        return None
    
    if data[0] != ord('Q'):
        return None
    
    length = struct.unpack('!I', data[1:5])[0]
    if length < 5:
        return None
    
    if len(data) < length:
        return None
    
    if length == 5:
        return ""
    
    query_bytes = data[5:length-1]
    if not query_bytes:
        return ""
    
    try:
        query = query_bytes.decode('utf-8', errors='replace')
        return query.strip()
    except Exception:
        return query_bytes.decode('utf-8', errors='replace').strip()

def parse_parse_message(data: bytes) -> Optional[str]:
    """Parse PostgreSQL Parse message (extended query protocol) to extract SQL query"""
    if len(data) < 5:
        return None
    
    if data[0] != ord('P'):
        return None
    
    length = struct.unpack('!I', data[1:5])[0]
    if length < 5:
        return None
    
    if len(data) < length:
        return None
    
    if length == 5:
        return ""
    
    pos = 5
    
    stmt_name_end = data.find(b'\x00', pos)
    if stmt_name_end == -1:
        return None
    stmt_name = data[pos:stmt_name_end].decode('utf-8', errors='replace')
    pos = stmt_name_end + 1
    
    if pos >= length:
        return None
    query_end = data.find(b'\x00', pos)
    if query_end == -1 or query_end >= length:
        return None
    
    query_bytes = data[pos:query_end]
    if not query_bytes:
        return ""
    
    try:
        query = query_bytes.decode('utf-8', errors='replace')
        return query.strip()
    except Exception:
        return query_bytes.decode('utf-8', errors='replace').strip()

async def send_authentication_request(writer, auth_type=3):
    response = b'R' + struct.pack('!I', 8) + struct.pack('!I', auth_type)
    writer.write(response)
    await writer.drain()

async def send_authentication_ok(writer):
    response = b'R' + struct.pack('!I', 8) + struct.pack('!I', 0)
    writer.write(response)
    await writer.drain()

async def send_ready_for_query(writer):
    response = b'Z' + struct.pack('!I', 5) + b'I'
    writer.write(response)
    await writer.drain()

async def send_parse_complete(writer):
    response = b'1' + struct.pack('!I', 4)
    writer.write(response)
    await writer.drain()

async def send_bind_complete(writer):
    response = b'2' + struct.pack('!I', 4)
    writer.write(response)
    await writer.drain()

async def send_execute_complete(writer):
    command_complete = b'C' + b'SELECT 0\x00'
    length = len(command_complete) + 4
    complete_response = struct.pack('!I', length) + command_complete[1:]
    writer.write(complete_response)
    await writer.drain()

async def send_error_response(writer, message: str, username: str = "unknown"):
    fields = [
        (b'S', b'FATAL'),
        (b'C', b'28P01'),
        (b'M', message.encode('utf-8', errors='replace')),
        (b'\x00', b''),
    ]
    message_content = b''.join([code + value + b'\x00' for code, value in fields])
    message_length = 4 + len(message_content)
    response = b'E' + struct.pack('!I', message_length) + message_content
    writer.write(response)
    await writer.drain()

async def send_query_response(writer, rows=None):
    if rows is None:
        rows = []
    
    if rows:
        row_desc = b'T'
        row_desc += struct.pack('!H', 1)
        row_desc += b'id\x00'
        row_desc += struct.pack('!I', 0)
        row_desc += struct.pack('!H', 0)
        row_desc += struct.pack('!I', 23)
        row_desc += struct.pack('!h', -1)
        row_desc += struct.pack('!H', 0)
        
        length = len(row_desc) + 4
        desc_response = struct.pack('!I', length) + row_desc[1:]
        writer.write(desc_response)
        await writer.drain()
        
        for row in rows:
            row_data = b'D'
            row_data += struct.pack('!H', 1)
            row_data += struct.pack('!I', 4)
            row_data += struct.pack('!I', row)
            length = len(row_data) + 4
            row_response = struct.pack('!I', length) + row_data[1:]
            writer.write(row_response)
            await writer.drain()
    
    command_complete = b'C' + b'SELECT 0\x00'
    length = len(command_complete) + 4
    complete_response = struct.pack('!I', length) + command_complete[1:]
    writer.write(complete_response)
    await writer.drain()
    
    await send_ready_for_query(writer)

async def handle_client(reader, writer):
    source_ip = writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else 'unknown'
    _buf = b''
    state = "startup"
    username = None
    database = None
    password = None
    request_text = ""
    connection_logged = False
    startup_params = {}
    prepared_statements = {}  # Store prepared statements: name -> query
    
    try:
        while True:
            if state == "startup":
                if len(_buf) < 8:
                    data = await reader.read(4096)
                    if not data:
                        if not connection_logged:
                            event_data = {
                                'honeypot_id': SERVICE_ID,
                                'event_type': 'postgres_connection',
                                'level': 1,
                                'source_ip': source_ip,
                                'details': {
                                    'username': username or 'unknown',
                                    'database': database or 'unknown',
                                    'request_text': request_text or 'connection attempt without data'
                                },
                                'honeytoken_check': None
                            }
                            send_event_to_backend(event_data)
                        break
                    _buf += data
                    continue
                
                length = struct.unpack('!I', _buf[0:4])[0]
                code = struct.unpack('!I', _buf[4:8])[0]
                
                if length == 8 and code in (80877103, 80877104):
                    _buf = _buf[8:]
                    writer.write(b'N')
                    await writer.drain()
                    continue
                
                if length < 8:
                    if not connection_logged:
                        event_data = {
                            'honeypot_id': SERVICE_ID,
                            'event_type': 'postgres_connection',
                            'level': 1,
                            'source_ip': source_ip,
                            'details': {
                                'username': username or 'unknown',
                                'database': database or 'unknown',
                                'request_text': request_text or 'invalid connection attempt'
                            },
                            'honeytoken_check': None
                        }
                        send_event_to_backend(event_data)
                    break
                
                if len(_buf) < length:
                    data = await reader.read(4096)
                    if not data:
                        if not connection_logged:
                            event_data = {
                                'honeypot_id': SERVICE_ID,
                                'event_type': 'postgres_connection',
                                'level': 1,
                                'source_ip': source_ip,
                                'details': {
                                    'username': username or 'unknown',
                                    'database': database or 'unknown',
                                    'request_text': request_text or 'incomplete connection attempt'
                                },
                                'honeytoken_check': None
                            }
                            send_event_to_backend(event_data)
                        break
                    _buf += data
                    continue
                
                msg = _buf[:length]
                _buf = _buf[length:]
                
                startup_params = parse_startup_message(msg)
                username = startup_params.get('user')
                database = startup_params.get('database', 'postgres')
                
                if not username:
                    event_data = {
                        'honeypot_id': SERVICE_ID,
                        'event_type': 'postgres_connection',
                        'level': 1,
                        'source_ip': source_ip,
                        'details': {
                            'username': 'unknown',
                            'database': database or 'unknown',
                            'request_text': 'connection attempt without username'
                        },
                        'honeytoken_check': None
                    }
                    send_event_to_backend(event_data)
                    break
                
                request_text = f"username={username}\ndatabase={database}\n"
                request_text += json.dumps(startup_params)
                
                await send_authentication_request(writer, auth_type=3)
                state = "authentication"
                continue
            
            if state == "authentication":
                if len(_buf) < 5:
                    data = await reader.read(4096)
                    if not data:
                        if not connection_logged:
                            event_data = {
                                'honeypot_id': SERVICE_ID,
                                'event_type': 'postgres_connection',
                                'level': 1,
                                'source_ip': source_ip,
                                'details': {
                                    'username': username,
                                    'database': database,
                                    'startup_params': startup_params,
                                    'request_text': request_text
                                },
                                'honeytoken_check': None
                            }
                            send_event_to_backend(event_data)
                        break
                    _buf += data
                    continue
                
                mtype = _buf[0:1]
                mlen = struct.unpack('!I', _buf[1:5])[0]
                total = 1 + mlen
                
                if mlen < 4:
                    if not connection_logged:
                        event_data = {
                            'honeypot_id': SERVICE_ID,
                            'event_type': 'postgres_connection',
                            'level': 1,
                            'source_ip': source_ip,
                            'details': {
                                'username': username,
                                'database': database,
                                'request_text': request_text
                            },
                            'honeytoken_check': None
                        }
                        send_event_to_backend(event_data)
                    break
                
                if len(_buf) < total:
                    data = await reader.read(4096)
                    if not data:
                        if not connection_logged:
                            event_data = {
                                'honeypot_id': SERVICE_ID,
                                'event_type': 'postgres_connection',
                                'level': 1,
                                'source_ip': source_ip,
                                'details': {
                                    'username': username,
                                    'database': database,
                                    'request_text': request_text
                                },
                                'honeytoken_check': None
                            }
                            send_event_to_backend(event_data)
                        break
                    _buf += data
                    continue
                
                payload = _buf[5:total]
                _buf = _buf[total:]
                
                if mtype == b'p':
                    pw = payload
                    if pw.endswith(b'\x00'):
                        pw = pw[:-1]
                    password = pw.decode('utf-8', errors='replace')
                    
                    request_text += f"\npassword={password}"
                    
                    event_data = {
                        'honeypot_id': SERVICE_ID,
                        'event_type': 'postgres_auth_attempt',
                        'level': 2,
                        'source_ip': source_ip,
                        'details': {
                            'username': username,
                            'password': password,
                            'database': database,
                            'request_text': request_text
                        },
                        'honeytoken_check': None
                    }
                    
                    send_event_to_backend(event_data)
                    connection_logged = True
                    
                    await send_authentication_ok(writer)
                    await send_ready_for_query(writer)
                    state = "ready"
                    continue
                else:
                    if not connection_logged:
                        event_data = {
                            'honeypot_id': SERVICE_ID,
                            'event_type': 'postgres_connection',
                            'level': 1,
                            'source_ip': source_ip,
                            'details': {
                                'username': username,
                                'database': database,
                                'request_text': request_text
                            },
                            'honeytoken_check': None
                        }
                        send_event_to_backend(event_data)
                    break
            
            if state == "ready":
                if len(_buf) < 5:
                    data = await reader.read(4096)
                    if not data:
                        break
                    _buf += data
                    continue
                
                msg_type = _buf[0:1]
                mlen = struct.unpack('!I', _buf[1:5])[0]
                total = 1 + mlen
                
                if mlen < 4:
                    print(f"[POSTGRES-HONEYPOT] Invalid message length: {mlen}")
                    break
                
                if len(_buf) < total:
                    data = await reader.read(4096)
                    if not data:
                        break
                    _buf += data
                    continue
                
                msg_data = _buf[:total]
                _buf = _buf[total:]
                
                msg_type_char = msg_type.decode('latin-1', errors='replace')
                raw_preview = msg_data[:min(100, len(msg_data))].hex() if len(msg_data) > 0 else ''
                print(f"[POSTGRES-HONEYPOT] Received message type: '{msg_type_char}' (0x{msg_type.hex()}), length: {mlen}, raw: {raw_preview}")
                
                if msg_type == b'Q':
                    query = parse_query_message(msg_data)
                    if query is not None and query.strip():
                        request_text += f"\nquery={query}"
                        
                        event_data = {
                            'honeypot_id': SERVICE_ID,
                            'event_type': 'postgres_query',
                            'level': 2,
                            'source_ip': source_ip,
                            'details': {
                                'username': username,
                                'password': password,
                                'database': database,
                                'query': query,
                                'request_text': request_text
                            },
                            'honeytoken_check': None
                        }
                        
                        print(f"[POSTGRES-HONEYPOT] Query received: {query}")
                        send_event_to_backend(event_data)
                        
                        await send_query_response(writer)
                    else:
                        if query is None:
                        print(f"[POSTGRES-HONEYPOT] Failed to parse query message, raw: {msg_data.hex()}")
                        elif not query.strip():
                            print(f"[POSTGRES-HONEYPOT] Empty query received")
                        await send_ready_for_query(writer)
                
                elif msg_type == b'X':
                    print(f"[POSTGRES-HONEYPOT] Terminate message received")
                    break
                elif msg_type == b'P':
                    query = parse_parse_message(msg_data)
                    if query is not None:
                        if len(msg_data) >= 5:
                            pos = 5
                            stmt_name_end = msg_data.find(b'\x00', pos)
                            if stmt_name_end != -1:
                                stmt_name = msg_data[pos:stmt_name_end].decode('utf-8', errors='replace')
                                prepared_statements[stmt_name] = query
                        
                        request_text += f"\nparse_query={query}"
                        
                        event_data = {
                            'honeypot_id': SERVICE_ID,
                            'event_type': 'postgres_query',
                            'level': 2,
                            'source_ip': source_ip,
                            'details': {
                                'username': username,
                                'password': password,
                                'database': database,
                                'query': query,
                                'query_type': 'parse',
                                'request_text': request_text
                            },
                            'honeytoken_check': None
                        }
                        
                        print(f"[POSTGRES-HONEYPOT] Parse query received: {query}")
                        send_event_to_backend(event_data)
                    else:
                        print(f"[POSTGRES-HONEYPOT] Failed to parse Parse message, raw: {msg_data.hex()}")
                    await send_parse_complete(writer)
                elif msg_type == b'B':
                    print(f"[POSTGRES-HONEYPOT] Bind message received")
                    await send_bind_complete(writer)
                elif msg_type == b'E':
                    query = None
                    stmt_name = None
                    if len(msg_data) >= 5:
                        pos = 5
                        stmt_name_end = msg_data.find(b'\x00', pos)
                        if stmt_name_end != -1:
                            stmt_name = msg_data[pos:stmt_name_end].decode('utf-8', errors='replace')
                            query = prepared_statements.get(stmt_name, None)
                    
                    if query:
                        request_text += f"\nexecute_query={query}"
                        
                        event_data = {
                            'honeypot_id': SERVICE_ID,
                            'event_type': 'postgres_query',
                            'level': 2,
                            'source_ip': source_ip,
                            'details': {
                                'username': username,
                                'password': password,
                                'database': database,
                                'query': query,
                                'query_type': 'execute',
                                'request_text': request_text
                            },
                            'honeytoken_check': None
                        }
                        
                        print(f"[POSTGRES-HONEYPOT] Execute query received: {query} (stmt: {stmt_name})")
                        send_event_to_backend(event_data)
                    else:
                        print(f"[POSTGRES-HONEYPOT] Execute message received (stmt: {stmt_name}, available: {list(prepared_statements.keys())})")
                        if stmt_name:
                            event_data = {
                                'honeypot_id': SERVICE_ID,
                                'event_type': 'postgres_execute',
                                'level': 1,
                                'source_ip': source_ip,
                                'details': {
                                    'username': username,
                                    'password': password,
                                    'database': database,
                                    'statement_name': stmt_name,
                                    'available_statements': list(prepared_statements.keys()),
                                    'request_text': request_text
                                },
                                'honeytoken_check': None
                            }
                            send_event_to_backend(event_data)
                    await send_execute_complete(writer)
                    await send_ready_for_query(writer)
                elif msg_type == b'D':
                    print(f"[POSTGRES-HONEYPOT] Describe message received")
                    await send_ready_for_query(writer)
                elif msg_type == b'C':
                    print(f"[POSTGRES-HONEYPOT] Close message received")
                    await send_ready_for_query(writer)
                elif msg_type == b'H':
                    print(f"[POSTGRES-HONEYPOT] Flush message received")
                    await send_ready_for_query(writer)
                elif msg_type == b'S':
                    print(f"[POSTGRES-HONEYPOT] Sync message received")
                    await send_ready_for_query(writer)
                else:
                    print(f"[POSTGRES-HONEYPOT] Unknown message type: '{msg_type_char}' (0x{msg_type.hex()}), length: {mlen}, raw: {msg_data[:min(50, len(msg_data))].hex()}")
                    if len(msg_data) > 5:
                        try:
                            potential_text = msg_data[5:min(200, len(msg_data)-1)].decode('utf-8', errors='replace')
                            if potential_text.strip():
                                print(f"[POSTGRES-HONEYPOT] Potential text in unknown message: {potential_text[:100]}")
                                event_data = {
                                    'honeypot_id': SERVICE_ID,
                                    'event_type': 'postgres_unknown_message',
                                    'level': 1,
                                    'source_ip': source_ip,
                                    'details': {
                                        'username': username,
                                        'password': password,
                                        'database': database,
                                        'message_type': msg_type_char,
                                        'message_hex': msg_type.hex(),
                                        'potential_text': potential_text,
                                        'request_text': request_text
                                    },
                                    'honeytoken_check': None
                                }
                                send_event_to_backend(event_data)
                        except Exception:
                            pass
                    await send_ready_for_query(writer)
    
    except Exception as e:
        print(f"[POSTGRES-HONEYPOT] Connection error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    
    print(f"[POSTGRES-HONEYPOT] PostgreSQL Honeypot started on {HOST}:{PORT}")
    print(f"[POSTGRES-HONEYPOT] Service ID: {SERVICE_ID}")
    print(f"[POSTGRES-HONEYPOT] API URL: {API_URL}")
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[POSTGRES-HONEYPOT] Shutting down...")

