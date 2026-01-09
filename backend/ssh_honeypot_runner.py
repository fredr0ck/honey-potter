#!/usr/bin/env python3
import os
import sys
import base64
import binascii
import hashlib
import random
import json
import requests
from warnings import filterwarnings
filterwarnings("ignore")

from twisted.internet import reactor, endpoints, defer
from twisted.conch.ssh import factory, keys, userauth, connection, transport, channel
from twisted.conch import avatar, interfaces as conchinterfaces
from twisted.cred import portal, credentials, error
from twisted.logger import textFileLogObserver
from twisted.python import log
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except Exception:
    ed25519 = None
from zope.interface import implementer

SERVICE_ID = os.getenv('SERVICE_ID', 'unknown')
PORT = int(os.getenv('PORT', '2222'))
HOST = os.getenv('HOST', '0.0.0.0')
API_URL = os.getenv('API_URL', 'http://172.17.0.1:8000')
SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')
SSH_VERSION = os.getenv('SSH_VERSION', 'SSH-2.0-OpenSSH_7.4')

script_dir = os.path.dirname(os.path.abspath(__file__))

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
        print(f"[SSH-HONEYPOT] Failed to send event: {e}")
    return False

def _b2s(x):
    if x is None:
        return ""
    if isinstance(x, (bytes, bytearray)):
        return x.decode("utf-8", "replace")
    return str(x)

def _u32_be(b):
    if not b or len(b) < 4:
        return 0
    return int.from_bytes(b[:4], "big", signed=False)

def _get_ns(b):
    if not b or len(b) < 4:
        return b"", b""
    ln = _u32_be(b)
    if ln < 0:
        return b"", b""
    start = 4
    end = 4 + ln
    if end > len(b):
        return b"", b""
    return b[start:end], b[end:]

def _sha256_hex(b):
    return hashlib.sha256(b or b"").hexdigest()

def _hex_prefix(b, n=256):
    return binascii.hexlify((b or b"")[:n]).decode("ascii", "ignore")

def _b64_prefix(b, n=768):
    try:
        return base64.b64encode((b or b"")[:n]).decode("ascii", "ignore")
    except Exception:
        return ""

def _printable_ratio(b):
    if not b:
        return 1.0
    p = 0
    for c in b:
        if c in (9, 10, 13) or (32 <= c <= 126):
            p += 1
    return p / max(1, len(b))

def _ssh_fp_sha256_from_blob(key_blob):
    try:
        digest = hashlib.sha256(key_blob).digest()
        return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")
    except Exception:
        return ""

def getRSAKeys():
    keys_dir = os.environ.get('SSH_KEYS_DIR', '/tmp/ssh_keys')
    os.makedirs(keys_dir, exist_ok=True)
    
    public_key_path = os.path.join(keys_dir, "id_rsa.pub")
    private_key_path = os.path.join(keys_dir, "id_rsa")
    
    if not (os.path.exists(public_key_path) and os.path.exists(private_key_path)):
        ssh_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        private_key = ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        try:
            with open(public_key_path, "wb") as key_file:
                key_file.write(public_key)
            with open(private_key_path, "wb") as key_file:
                key_file.write(private_key)
            os.chmod(public_key_path, 0o644)
            os.chmod(private_key_path, 0o600)
        except Exception as e:
            print(f"[SSH-HONEYPOT] Warning: Could not save keys to disk: {e}")
    
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = key_file.read()
        with open(private_key_path, "rb") as key_file:
            private_key = key_file.read()
    except Exception as e:
        print(f"[SSH-HONEYPOT] Warning: Could not load keys from disk, generating new ones: {e}")
        ssh_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        private_key = ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    
    return public_key, private_key

def _load_or_create_hostkey(path_base, make_key_fn, pub_format="openssh"):
    keys_dir = os.environ.get('SSH_KEYS_DIR', '/tmp/ssh_keys')
    os.makedirs(keys_dir, exist_ok=True)
    
    key_name = os.path.basename(path_base)
    priv_path = os.path.join(keys_dir, key_name)
    pub_path = os.path.join(keys_dir, key_name + ".pub")
    
    if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
        key = make_key_fn()
        pub = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        try:
            priv = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        except Exception:
            priv = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        try:
            with open(priv_path, "wb") as f:
                f.write(priv)
            with open(pub_path, "wb") as f:
                f.write(pub)
            os.chmod(priv_path, 0o600)
            os.chmod(pub_path, 0o644)
        except Exception as e:
            print(f"[SSH-HONEYPOT] Warning: Could not save host key to disk: {e}")
    
    try:
        with open(pub_path, "rb") as f:
            pub_b = f.read()
        with open(priv_path, "rb") as f:
            priv_b = f.read()
    except Exception as e:
        print(f"[SSH-HONEYPOT] Warning: Could not load host key from disk, generating new one: {e}")
        key = make_key_fn()
        pub_b = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        try:
            priv_b = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        except Exception:
            priv_b = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
    
    return pub_b, priv_b

def getHostKeyDicts():
    rsa_pub, rsa_priv = getRSAKeys()
    publicKeys = {}
    privateKeys = {}
    
    try:
        publicKeys[b"ssh-rsa"] = keys.Key.fromString(data=rsa_pub)
        privateKeys[b"ssh-rsa"] = keys.Key.fromString(data=rsa_priv)
    except Exception:
        pass
    
    try:
        ecdsa_pub, ecdsa_priv = _load_or_create_hostkey(
            "ssh_host_ecdsa_key",
            lambda: ec.generate_private_key(ec.SECP256R1()),
        )
        publicKeys[b"ecdsa-sha2-nistp256"] = keys.Key.fromString(data=ecdsa_pub)
        privateKeys[b"ecdsa-sha2-nistp256"] = keys.Key.fromString(data=ecdsa_priv)
    except Exception:
        pass
    
    if ed25519 is not None:
        try:
            ed_pub, ed_priv = _load_or_create_hostkey(
                "ssh_host_ed25519_key",
                lambda: ed25519.Ed25519PrivateKey.generate(),
            )
            try:
                publicKeys[b"ssh-ed25519"] = keys.Key.fromString(data=ed_pub)
                privateKeys[b"ssh-ed25519"] = keys.Key.fromString(data=ed_priv)
            except Exception:
                pass
        except Exception:
            pass
    
    if not publicKeys or not privateKeys:
        publicKeys = {b"ssh-rsa": keys.Key.fromString(data=getRSAKeys()[0])}
        privateKeys = {b"ssh-rsa": keys.Key.fromString(data=getRSAKeys()[1])}
    
    return publicKeys, privateKeys

@implementer(portal.IRealm)
class SimpleSSHRealm:
    def requestAvatar(self, avatar_id, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            avatar_obj = SimpleSSHAvatar(avatar_id)
            try:
                transport = getattr(mind, 'transport', None)
                if transport:
                    transport_obj = getattr(transport, 'transport', None)
                    if transport_obj:
                        peer = transport_obj.getPeer()
                        avatar_obj.source_ip = getattr(peer, "host", "unknown")
            except Exception:
                pass
            return interfaces[0], avatar_obj, lambda: None
        raise Exception("No supported interfaces found.")

class SimpleSSHAvatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.commands = []
        self.source_ip = None
    
    def getSourceIP(self):
        try:
            transport = getattr(self, 'conn', None)
            if transport:
                transport_obj = getattr(transport, 'transport', None)
                if transport_obj:
                    peer = transport_obj.getPeer()
                    return getattr(peer, "host", "unknown")
        except Exception:
            pass
        return self.source_ip or "unknown"

class CustomSSHUserAuthServer(userauth.SSHUserAuthServer):
    def ssh_USERAUTH_REQUEST(self, packet):
        try:
            user_b, rest = _get_ns(packet)
            svc_b, rest = _get_ns(rest)
            meth_b, rest = _get_ns(rest)
            meth = _b2s(meth_b).lower()
            
            peer = self.transport.transport.getPeer()
            us = self.transport.transport.getHost()
            source_ip = getattr(peer, "host", "")
            
            username = _b2s(user_b)
            password = None
            level = 1
            honeytoken_check = None
            
            if meth == "password":
                try:
                    if rest and len(rest) > 0:
                        change_password = int(rest[0]) if rest else 0
                        password_rest = rest[1:] if len(rest) > 1 else b""
                        password_b, _ = _get_ns(password_rest)
                        password = _b2s(password_b)
                    else:
                        password = ""
                        change_password = 0
                    
                    request_text = f"username={username}\npassword={password}\nmethod={meth}\nservice={_b2s(svc_b)}\nchange_password={change_password}"
                    
                    event_data = {
                        'honeypot_id': SERVICE_ID,
                        'event_type': 'ssh_auth_attempt',
                        'level': 2,
                        'source_ip': source_ip,
                        'details': {
                            'username': username,
                            'password': password,
                            'method': meth,
                            'service': _b2s(svc_b),
                            'change_password': change_password,
                            'local_version': _b2s(getattr(self.transport, "ourVersionString", b"")),
                            'remote_version': _b2s(getattr(self.transport, "otherVersionString", b"")),
                            'request_text': request_text
                        },
                        'honeytoken_check': None
                    }
                    
                    send_event_to_backend(event_data)
                    print(f"[SSH-HONEYPOT] Auth attempt - Username: {username}, Password: {password}")
                except Exception as e:
                    print(f"[SSH-HONEYPOT] Failed to parse password: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                if meth not in ("none", "publickey"):
                    request_text = f"username={username}\nmethod={meth}\nservice={_b2s(svc_b)}"
                    
                    event_data = {
                        'honeypot_id': SERVICE_ID,
                        'event_type': 'ssh_connection',
                        'level': level,
                        'source_ip': source_ip,
                        'details': {
                            'username': username,
                            'method': meth,
                            'service': _b2s(svc_b),
                            'local_version': _b2s(getattr(self.transport, "ourVersionString", b"")),
                            'remote_version': _b2s(getattr(self.transport, "otherVersionString", b"")),
                            'request_text': request_text
                        },
                        'honeytoken_check': honeytoken_check
                    }
                    
                    if meth == "publickey":
                        has_sig = 0
                        try:
                            has_sig = int(rest[0]) if rest else 0
                            rest2 = rest[1:] if len(rest) > 1 else b""
                        except Exception:
                            has_sig = 0
                            rest2 = b""
                        
                        alg_b, rest2 = _get_ns(rest2)
                        key_blob, rest2 = _get_ns(rest2)
                        
                        event_data['details'].update({
                            'publickey_has_signature': has_sig,
                            'public_key_alg': _b2s(alg_b),
                            'public_key_fp_sha256': _ssh_fp_sha256_from_blob(key_blob),
                            'public_key_b64_prefix': _b64_prefix(key_blob, n=512),
                            'public_key_len': len(key_blob or b""),
                        })
                    
                    send_event_to_backend(event_data)
                    print(f"[SSH-HONEYPOT] Connection attempt - Username: {username}, Method: {meth}")
        except Exception as e:
            print(f"[SSH-HONEYPOT] Error in ssh_USERAUTH_REQUEST: {e}")
        
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

class CustomSSHServerTransport(transport.SSHServerTransport):
    def __init__(self, our_version_string):
        self.ourVersionString = our_version_string.encode()
        self._conn_id = format(random.getrandbits(64), "x")
        self._raw_events = 0
        self._raw_events_max = 3
        self._raw_max_bytes = 8192
        self._ver_logged = False
        self._connection_logged = False
        self._kexinit_logged = False
        self.source_ip = None
        transport.SSHServerTransport.__init__(self)

    def connectionMade(self):
        try:
            peer = self.transport.getPeer()
            us = self.transport.getHost()
            self.source_ip = getattr(peer, "host", "")
            self._connection_logged = True
            
            event_data = {
                'honeypot_id': SERVICE_ID,
                'event_type': 'ssh_connection',
                'level': 1,
                'source_ip': self.source_ip,
                'details': {
                    'src_port': getattr(peer, "port", ""),
                    'dst_host': getattr(us, "host", ""),
                    'dst_port': getattr(us, "port", ""),
                    'local_version': _b2s(getattr(self, "ourVersionString", b"")),
                    'conn_id': self._conn_id,
                    'request_text': f"new_connection from {self.source_ip}"
                },
                'honeytoken_check': None
            }
            
            send_event_to_backend(event_data)
            print(f"[SSH-HONEYPOT] New connection from {self.source_ip}")
        except Exception as e:
            print(f"[SSH-HONEYPOT] Error in connectionMade: {e}")
        
        return transport.SSHServerTransport.connectionMade(self)

    def dataReceived(self, data):
        if not self._ver_logged:
            try:
                self._log_raw_in(data)
            except Exception:
                pass
        out = transport.SSHServerTransport.dataReceived(self, data)
        
        try:
            if getattr(self, "gotVersion", False) and not self._ver_logged:
                self._ver_logged = True
        except Exception:
            pass
        
        return out

    def _log_raw_in(self, data):
        if self._raw_events >= self._raw_events_max:
            return
        self._raw_events += 1

    def ssh_KEXINIT(self, packet):
        try:
            if not self._kexinit_logged:
                self._kexinit_logged = True
                cookie = packet[:16]
                rest = packet[16:]
                kex, rest = _get_ns(rest)
                hostkey, rest = _get_ns(rest)
                
                peer = self.transport.getPeer()
                us = self.transport.getHost()
                
                event_data = {
                    'honeypot_id': SERVICE_ID,
                    'event_type': 'ssh_connection',
                    'level': 1,
                    'source_ip': self.source_ip or getattr(peer, "host", ""),
                    'details': {
                        'src_port': getattr(peer, "port", ""),
                        'dst_host': getattr(us, "host", ""),
                        'dst_port': getattr(us, "port", ""),
                        'kex_algs': _b2s(kex),
                        'host_key_algs': _b2s(hostkey),
                        'local_version': _b2s(getattr(self, "ourVersionString", b"")),
                        'remote_version': _b2s(getattr(self, "otherVersionString", b"")),
                        'conn_id': self._conn_id,
                        'request_text': f"kexinit: kex={_b2s(kex)}, hostkey={_b2s(hostkey)}"
                    },
                    'honeytoken_check': None
                }
                
                send_event_to_backend(event_data)
        except Exception:
            pass
        
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

class CustomSSHConnection(connection.SSHConnection):
    def __init__(self):
        connection.SSHConnection.__init__(self)
        self.username = None
        self.source_ip = None
    
    def serviceStarted(self):
        try:
            transport = self.transport
            if transport:
                transport_obj = getattr(transport, 'transport', None)
                if transport_obj:
                    peer = transport_obj.getPeer()
                    self.source_ip = getattr(peer, "host", "unknown")
        except Exception:
            pass
        connection.SSHConnection.serviceStarted(self)
    
    def gotGlobalRequest(self, requestType, data):
        return 0
    
    def requestService(self, service):
        if service.name == b"ssh-userauth":
            return True
        return False
    
    def getSourceIP(self):
        try:
            transport = self.transport
            if transport:
                transport_obj = getattr(transport, 'transport', None)
                if transport_obj:
                    peer = transport_obj.getPeer()
                    return getattr(peer, "host", "unknown")
        except Exception:
            pass
        return self.source_ip or "unknown"
    
    def lookupChannel(self, channelType, windowSize, maxPacket, data):
        if channelType == b"session":
            avatar_obj = getattr(self, 'avatar', None)
            username = getattr(avatar_obj, 'username', 'unknown') if avatar_obj else 'unknown'
            ch = CustomSSHChannel(remoteWindow=windowSize, remoteMaxPacket=maxPacket, data=data, avatar=avatar_obj)
            ch.username = username
            ch.conn = self
            return ch
        return None

class CustomSSHChannel(channel.SSHChannel):
    def __init__(self, *args, **kwargs):
        channel.SSHChannel.__init__(self, *args, **kwargs)
        self.username = None
        self.command = None
        self.conn = None
    
    def channelOpen(self, specificData):
        pass
    
    def request_exec(self, data):
        try:
            command_b, _ = _get_ns(data)
            command = _b2s(command_b)
            self.command = command
            
            source_ip = "unknown"
            try:
                conn = getattr(self, 'conn', None)
                if conn:
                    source_ip = conn.getSourceIP()
            except Exception:
                pass
            
            username = self.username or "unknown"
            request_text = f"username={username}\ncommand={command}"
            
            event_data = {
                'honeypot_id': SERVICE_ID,
                'event_type': 'ssh_command',
                'level': 2,
                'source_ip': source_ip,
                'details': {
                    'username': username,
                    'command': command,
                    'request_text': request_text
                },
                'honeytoken_check': None
            }
            
            send_event_to_backend(event_data)
            print(f"[SSH-HONEYPOT] Command executed - Username: {username}, Command: {command}")
            
            self.write(b"Command executed (honeypot)\n")
            self.conn.sendEOF(self)
        except Exception as e:
            print(f"[SSH-HONEYPOT] Error in request_exec: {e}")
        
        return True
    
    def request_pty_req(self, data):
        return True
    
    def request_shell(self, data):
        return True
    
    def dataReceived(self, data):
        try:
            command = _b2s(data).strip()
            if command:
                source_ip = "unknown"
                try:
                    conn = getattr(self, 'conn', None)
                    if conn:
                        source_ip = conn.getSourceIP()
                except Exception:
                    pass
                
                username = self.username or "unknown"
                request_text = f"username={username}\ncommand={command}"
                
                event_data = {
                    'honeypot_id': SERVICE_ID,
                    'event_type': 'ssh_command',
                    'level': 2,
                    'source_ip': source_ip,
                    'details': {
                        'username': username,
                        'command': command,
                        'request_text': request_text
                    },
                    'honeytoken_check': None
                }
                
                send_event_to_backend(event_data)
                print(f"[SSH-HONEYPOT] Command executed - Username: {username}, Command: {command}")
                
                self.write(b"$ ")
        except Exception as e:
            print(f"[SSH-HONEYPOT] Error in dataReceived: {e}")
        
        return channel.SSHChannel.dataReceived(self, data)

class SimpleSSHFactory(factory.SSHFactory):
    def __init__(self, our_version_string):
        self.ourVersionString = our_version_string
        self.publicKeys, self.privateKeys = getHostKeyDicts()

    services = {
        b"ssh-userauth": CustomSSHUserAuthServer,
        b"ssh-connection": CustomSSHConnection,
    }

    def buildProtocol(self, addr):
        t = CustomSSHServerTransport(self.ourVersionString)
        try:
            t.supportedPublicKeys = list(self.privateKeys.keys())
        except Exception:
            t.supportedPublicKeys = self.privateKeys.keys()
        t.factory = self
        return t

class LoggingPasswordChecker:
    credentialInterfaces = [credentials.IUsernamePassword]
    
    def requestAvatarId(self, creds):
        username = creds.username if hasattr(creds, 'username') else 'unknown'
        password = creds.password if hasattr(creds, 'password') else ''
        
        if not password:
            password = str(creds.password) if creds.password else ''
        
        source_ip = 'unknown'
        try:
            transport = getattr(creds, 'transport', None)
            if transport:
                transport_obj = getattr(transport, 'transport', None)
                if transport_obj:
                    peer = transport_obj.getPeer()
                    source_ip = getattr(peer, "host", "unknown")
        except Exception:
            pass
        
        request_text = f"username={username}\npassword={password}"
        
        event_data = {
            'honeypot_id': SERVICE_ID,
            'event_type': 'ssh_auth_attempt',
            'level': 2,
            'source_ip': source_ip,
            'details': {
                'username': username,
                'password': password,
                'request_text': request_text
            },
            'honeytoken_check': None
        }
        
        send_event_to_backend(event_data)
        print(f"[SSH-HONEYPOT] Login attempt - Username: {username}, Password: {password}")
        
        return defer.fail(error.UnauthorizedLogin())

def main():
    print(f"[SSH-HONEYPOT] SSH Honeypot starting on {HOST}:{PORT}")
    print(f"[SSH-HONEYPOT] Service ID: {SERVICE_ID}")
    print(f"[SSH-HONEYPOT] API URL: {API_URL}")
    print(f"[SSH-HONEYPOT] SSH Version: {SSH_VERSION}")
    
    ssh_factory = SimpleSSHFactory(SSH_VERSION)
    ssh_realm = SimpleSSHRealm()
    ssh_portal = portal.Portal(ssh_realm)
    ssh_portal.registerChecker(LoggingPasswordChecker())
    ssh_factory.portal = ssh_portal
    
    endpoint = endpoints.TCP4ServerEndpoint(reactor, PORT, interface=HOST)
    endpoint.listen(ssh_factory)
    
    reactor.run()

if __name__ == "__main__":
    main()

