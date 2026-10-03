import json
import threading
import ssl
import tempfile
import subprocess
import shutil
from pathlib import Path
import unittest
import urllib.request
import urllib.error
from server import Store, ApiError, Server

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.s = Store(lambda: self.now)
        self.owner = self.s.create('owner-ip')
        self.operator = self.s.join('operator-ip', self.owner['code'], 'Falaye')
        self.ot, self.pt = self.owner['token'], self.operator['token']
    def fails(self, code, fn):
        with self.assertRaises(ApiError) as error:
            fn()
        self.assertEqual(error.exception.status, code)
    def accept(self, control=True):
        self.s.action(self.ot, 'accept', {'control': control})
    def test_owner_only_consent_and_one_time_code(self):
        self.fails(403, lambda: self.s.action(self.pt, 'accept'))
        self.fails(409, lambda: self.s.action(self.pt, 'frame'))
        self.fails(404, lambda: self.s.join('third', self.owner['code'], 'Other'))
        self.accept(False)
        self.fails(403, lambda: self.s.action(self.pt, 'command', {'kind': 'home'}))
    def test_pause_stop_clear_buffers_and_permissions(self):
        self.accept()
        self.s.action(self.ot, 'upload_frame', raw=b'\xff\xd8example\xff\xd9')
        self.s.action(self.pt, 'command', {'kind':'home'})
        self.s.action(self.ot, 'pause', {'paused':True})
        self.fails(409, lambda: self.s.action(self.pt, 'frame'))
        self.s.action(self.ot, 'pause', {'paused':False})
        self.assertEqual(self.s.action(self.ot, 'commands')['commands'], [])
        self.assertIsNone(self.s.action(self.pt, 'frame'))
        self.s.action(self.ot, 'stop')
        self.fails(409, lambda: self.s.action(self.pt, 'command', {'kind':'home'}))
        self.assertFalse(self.s.action(self.pt, 'state')['control'])
    def test_cross_session_isolation(self):
        self.accept()
        second = self.s.create('another-ip')
        self.fails(409, lambda: self.s.action(second['token'], 'frame'))
        self.fails(401, lambda: self.s.action('invalid-token', 'state'))
        self.assertEqual(self.s.action(second['token'], 'state')['state'], 'waiting')
    def test_command_validation_expiry_and_roles(self):
        self.accept()
        for command in ({'kind':'tap','x':2,'y':0}, {'kind':'tap','x':float('nan'),'y':0}, {'kind':'extract'}):
            self.fails(400, lambda c=command: self.s.action(self.pt, 'command', c))
        self.fails(403, lambda: self.s.action(self.ot, 'command', {'kind':'home'}))
        self.s.action(self.pt, 'command', {'kind':'tap','x':0.2,'y':0.4})
        self.now += 3
        self.assertEqual(self.s.action(self.ot, 'commands')['commands'], [])
    def test_peer_disconnection_revokes_session(self):
        self.accept()
        self.now += 26
        self.fails(401, lambda: self.s.action(self.pt, 'state'))
        self.assertEqual(len(self.s.sessions), 0)
    def test_join_rate_limit(self):
        for i in range(8):
            self.fails(404, lambda: self.s.join('attacker', '000', 'x'))
        self.fails(429, lambda: self.s.join('attacker', '000', 'x'))
    def test_frame_validation_and_role(self):
        self.accept()
        self.fails(403, lambda: self.s.action(self.pt, 'upload_frame', raw=b'\xff\xd8x\xff\xd9'))
        self.fails(400, lambda: self.s.action(self.ot, 'upload_frame', raw=b'bad'))
    def test_code_expiry(self):
        fresh = self.s.create('fresh')
        self.now += 301
        self.fails(404, lambda: self.s.join('op2', fresh['code'], 'x'))

class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(('127.0.0.1',0))
        cls.base = 'http://127.0.0.1:%d' % cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
    def request(self, path, body=None, token=None):
        headers = {'Content-Type':'application/json'}
        if token: headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
    def test_actual_http_consent_and_stop(self):
        status, owner = self.request('/v1/create', {})
        self.assertEqual(status, 201)
        status, op = self.request('/v1/join', {'code':owner['code'], 'name':'Test'})
        self.assertEqual(status, 200)
        self.assertEqual(self.request('/v1/accept', {}, op['token'])[0], 403)
        self.assertEqual(self.request('/v1/accept', {'control':True}, owner['token'])[0], 200)
        self.assertEqual(self.request('/v1/command', {'kind':'back'}, op['token'])[0], 200)
        status, commands = self.request('/v1/commands', token=owner['token'])
        self.assertEqual(commands['commands'], [{'kind':'back'}])
        self.request('/v1/stop', {}, owner['token'])
        self.assertEqual(self.request('/v1/command', {'kind':'back'}, op['token'])[0], 409)
    def test_missing_auth_and_bad_payload(self):
        self.assertEqual(self.request('/v1/state')[0], 401)
        self.assertEqual(self.request('/v1/create', [1])[0], 400)
        self.assertEqual(self.request('/v1/join', {'code':42})[0], 400)

class HttpsTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL nécessaire pour le certificat temporaire')
    def test_tls_frame_roundtrip_message_pause_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp) / 'cert.pem', Path(tmp) / 'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost',
                '-addext','subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server = Server(('127.0.0.1', 0))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(cert, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            context = ssl.create_default_context(cafile=str(cert))
            base = 'https://localhost:%d' % server.server_port
            def call(path, data=None, token=None, raw=False):
                headers = {'Content-Type':'image/jpeg' if raw else 'application/json'}
                if token: headers['Authorization'] = 'Bearer ' + token
                body = data if raw else None if data is None else json.dumps(data).encode()
                req = urllib.request.Request(base + path, data=body, headers=headers)
                with urllib.request.urlopen(req, context=context) as r:
                    b = r.read()
                    return b if r.headers.get('Content-Type') == 'image/jpeg' else json.loads(b)
            try:
                owner = call('/v1/create', {})
                op = call('/v1/join', {'code':owner['code'],'name':'Test HTTPS'})
                call('/v1/accept', {'control':True}, owner['token'])
                jpeg = (Path(__file__).resolve().parent / 'assets/logo-original.jpg').read_bytes()
                call('/v1/frame', jpeg, owner['token'], raw=True)
                self.assertEqual(call('/v1/frame', token=op['token']), jpeg)
                call('/v1/message', {'text':'Bonjour'}, op['token'])
                self.assertEqual(call('/v1/state', token=owner['token'])['messages'][0]['text'], 'Bonjour')
                call('/v1/pause', {'paused':True}, owner['token'])
                with self.assertRaises(urllib.error.HTTPError) as error:
                    call('/v1/frame', token=op['token'])
                self.assertEqual(error.exception.code, 409)
                call('/v1/stop', {}, owner['token'])
                self.assertEqual(call('/v1/state', token=op['token'])['state'], 'closed')
            finally:
                server.shutdown()
                server.server_close()

if __name__ == '__main__':
    unittest.main()
