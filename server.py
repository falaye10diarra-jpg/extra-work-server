#!/usr/bin/env python3
"""Extra Work 0.1: consent-based, in-memory HTTPS screen relay. Python 3.10+."""
import argparse
import collections
import json
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_FRAME = 512 * 1024
SESSION_SECONDS = 15 * 60
CODE_SECONDS = 5 * 60
PEER_TIMEOUT = 25

class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message

class Store:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.RLock()
        self.sessions = {}
        self.tokens = {}
        self.codes = {}
        self.attempts = collections.defaultdict(collections.deque)

    def limit(self, key, maximum=10, window=60):
        now = self.clock()
        bucket = self.attempts[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= maximum:
            raise ApiError(429, 'Trop de demandes. Réessayez plus tard.')
        bucket.append(now)

    def purge(self):
        now = self.clock()
        for sid, s in list(self.sessions.items()):
            expired = now >= s['expires']
            lost = s['state'] in ('active', 'paused') and (
                now - s['owner_seen'] > PEER_TIMEOUT or now - s['operator_seen'] > PEER_TIMEOUT)
            if expired or lost:
                self.close(s)
                for token in (s['owner_token'], s.get('operator_token')):
                    if token:
                        self.tokens.pop(token, None)
                self.codes.pop(s['code'], None)
                self.sessions.pop(sid, None)
        for key, bucket in list(self.attempts.items()):
            if not bucket or now - bucket[-1] > 120:
                self.attempts.pop(key, None)

    def create(self, ip):
        with self.lock:
            self.purge()
            self.limit(('create', ip), 5)
            if len(self.sessions) >= 200:
                raise ApiError(503, 'Serveur occupé.')
            code = ''.join(secrets.choice('0123456789') for _ in range(8))
            while code in self.codes:
                code = ''.join(secrets.choice('0123456789') for _ in range(8))
            sid, token = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
            now = self.clock()
            s = dict(id=sid, code=code, owner_token=token, operator_token=None,
                     operator_name='', state='waiting', control=False,
                     created=now, expires=now + SESSION_SECONDS, code_expires=now + CODE_SECONDS,
                     owner_seen=now, operator_seen=now, frame=None, commands=[], messages=[],
                     frame_seq=0, last_command=0, last_frame=-10)
            self.sessions[sid] = s
            self.tokens[token] = (sid, 'owner')
            self.codes[code] = sid
            return dict(token=token, code=code, expires_in=CODE_SECONDS)

    def join(self, ip, code, name):
        with self.lock:
            self.purge()
            self.limit(('join', ip), 8)
            sid = self.codes.get(code)
            s = self.sessions.get(sid)
            if not s or self.clock() >= s['code_expires'] or s['state'] != 'waiting':
                raise ApiError(404, 'Code expiré, utilisé ou incorrect.')
            token = secrets.token_urlsafe(32)
            s.update(operator_token=token, operator_name=name.strip()[:60] or 'Opérateur',
                     state='pending', operator_seen=self.clock())
            self.tokens[token] = (sid, 'operator')
            self.codes.pop(code, None)
            return dict(token=token, state='pending')

    def auth(self, token):
        self.purge()
        info = self.tokens.get(token)
        if not info:
            raise ApiError(401, 'Session absente ou expirée.')
        s = self.sessions[info[0]]
        s[info[1] + '_seen'] = self.clock()
        return s, info[1]

    def close(self, s):
        s.update(state='closed', frame=None, commands=[], messages=[], control=False)
        self.codes.pop(s['code'], None)

    def action(self, token, action, data=None, raw=None):
        with self.lock:
            s, role = self.auth(token)
            data = data or {}
            if action == 'state':
                return dict(state=s['state'], operator_name=s['operator_name'], control=s['control'],
                            frame_seq=s['frame_seq'], remaining=max(0, int(s['expires'] - self.clock())),
                            messages=s['messages'][-30:])
            if action == 'stop':
                self.close(s)
                return dict(state='closed')
            if s['state'] == 'closed':
                raise ApiError(409, 'Session arrêtée.')
            if action == 'accept':
                if role != 'owner':
                    raise ApiError(403, 'Seul le propriétaire peut accepter.')
                if s['state'] != 'pending':
                    raise ApiError(409, 'Aucune demande à accepter.')
                if type(data.get('control', False)) is not bool:
                    raise ApiError(400, 'Autorisation invalide.')
                s.update(state='active', control=data.get('control', False))
                return dict(state='active')
            if action == 'pause':
                if role != 'owner':
                    raise ApiError(403, 'Seul le propriétaire peut suspendre.')
                if s['state'] not in ('active', 'paused'):
                    raise ApiError(409, 'Session inactive.')
                s['state'] = 'paused' if data.get('paused', True) else 'active'
                s.update(frame=None, commands=[])
                return dict(state=s['state'])
            if s['state'] != 'active':
                raise ApiError(409, 'Session inactive ou suspendue.')
            if action == 'upload_frame':
                if role != 'owner':
                    raise ApiError(403, 'Rôle incorrect.')
                if not raw or len(raw) > MAX_FRAME or not raw.startswith(b'\xff\xd8') or not raw.endswith(b'\xff\xd9'):
                    raise ApiError(400, 'Image JPEG invalide ou trop grande.')
                if self.clock() - s['last_frame'] < 0.25:
                    raise ApiError(429, 'Fréquence trop élevée.')
                s['frame'], s['last_frame'] = bytes(raw), self.clock()
                s['frame_seq'] += 1
                return dict(sequence=s['frame_seq'])
            if action == 'frame':
                if role != 'operator':
                    raise ApiError(403, 'Rôle incorrect.')
                return s['frame']
            if action == 'command':
                if role != 'operator' or not s['control']:
                    raise ApiError(403, 'Contrôle non autorisé.')
                self.limit(('command', s['id']), 10, 1)
                kind = data.get('kind')
                if kind not in ('tap', 'swipe', 'back', 'home'):
                    raise ApiError(400, 'Commande inconnue.')
                cmd = dict(kind=kind, created=self.clock())
                if kind in ('tap', 'swipe'):
                    for key in ('x', 'y') + (('x2', 'y2') if kind == 'swipe' else ()):
                        value = data.get(key)
                        if type(value) not in (int, float) or not 0 <= value <= 1:
                            raise ApiError(400, 'Coordonnées invalides.')
                        cmd[key] = float(value)
                if len(s['commands']) >= 12:
                    raise ApiError(429, 'Trop de commandes en attente.')
                s['commands'].append(cmd)
                return dict(ok=True)
            if action == 'commands':
                if role != 'owner':
                    raise ApiError(403, 'Rôle incorrect.')
                cmds = [{k: v for k, v in c.items() if k != 'created'} for c in s['commands']
                        if self.clock() - c['created'] < 2]
                s['commands'] = []
                return dict(commands=cmds, control=s['control'])
            if action == 'message':
                self.limit(('message', s['id'], role), 10, 10)
                text = data.get('text', '')
                if not isinstance(text, str) or not text.strip() or len(text) > 500:
                    raise ApiError(400, 'Message invalide (500 caractères maximum).')
                s['messages'].append(dict(role=role, text=text.strip()))
                s['messages'] = s['messages'][-30:]
                return dict(ok=True)
            raise ApiError(404, 'Route inconnue.')

class Handler(BaseHTTPRequestHandler):
    server_version = 'ExtraWork/0.1'
    def log_message(self, *_):
        pass  # Never log pairing codes, tokens, frames or messages.
    def respond(self, status, body, content_type='application/json'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self.handle_api(False)
    def do_POST(self):
        self.handle_api(True)
    def handle_api(self, post):
        try:
            self.connection.settimeout(10)
            if self.path == '/health' and not post:
                return self.respond(200, dict(status='ok', version='0.1'))
            if self.path not in ('/v1/create', '/v1/join', '/v1/state', '/v1/accept', '/v1/stop',
                                  '/v1/pause', '/v1/frame', '/v1/command', '/v1/commands', '/v1/message'):
                raise ApiError(404, 'Route inconnue.')
            length = int(self.headers.get('Content-Length', '0'))
            if length < 0 or length > (MAX_FRAME if self.path == '/v1/frame' else 4096):
                raise ApiError(413, 'Contenu trop grand.')
            raw = self.rfile.read(length) if post else b''
            if len(raw) != length and post:
                raise ApiError(400, 'Contenu incomplet.')
            data = {} if self.path == '/v1/frame' or not raw else json.loads(raw)
            if not isinstance(data, dict):
                raise ApiError(400, 'Objet JSON requis.')
            store = self.server.store
            if self.path == '/v1/create' and post:
                return self.respond(201, store.create(self.client_address[0]))
            if self.path == '/v1/join' and post:
                code, name = data.get('code', ''), data.get('name', '')
                if not isinstance(code, str) or not isinstance(name, str):
                    raise ApiError(400, 'Code ou nom invalide.')
                return self.respond(200, store.join(self.client_address[0], code, name))
            action = self.path.split('/')[-1]
            allowed_post = ('accept', 'stop', 'pause', 'frame', 'command', 'message')
            allowed_get = ('state', 'frame', 'commands')
            if (post and action not in allowed_post) or (not post and action not in allowed_get):
                raise ApiError(405, 'Méthode incorrecte.')
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                raise ApiError(401, 'Authentification requise.')
            result = store.action(auth[7:], 'upload_frame' if action == 'frame' and post else action, data, raw)
            if action == 'frame' and not post:
                return self.respond(200 if result else 204, result or b'', 'image/jpeg')
            self.respond(200, result)
        except ApiError as e:
            self.respond(e.status, dict(error=e.message))
        except (ValueError, TypeError, UnicodeError):
            self.respond(400, dict(error='Requête invalide.'))
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store=None):
        super().__init__(address, Handler)
        self.store = store or Store()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error('--cert et --key sont requis ensemble')
    if args.host not in ('127.0.0.1', 'localhost', '::1') and not args.cert:
        parser.error('Exposition publique refusée sans certificat TLS. Utilisez un proxy HTTPS local.')
    server = Server((args.host, args.port))
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    def cleanup():
        while True:
            time.sleep(5)
            with server.store.lock:
                server.store.purge()
    threading.Thread(target=cleanup, daemon=True).start()
    print('Extra Work 0.1 — serveur démarré ; sessions en mémoire uniquement.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == '__main__':
    main()
