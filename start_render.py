"""Start only inside Render, where the edge proxy provides public HTTPS."""
import os
import threading
import time
from server import Server

def main():
    if os.environ.get('RENDER', '').lower() != 'true':
        raise SystemExit('Ce lanceur nécessite Render. En local, utilisez server.py sur 127.0.0.1 ou avec un certificat HTTPS.')
    port = int(os.environ.get('PORT', '10000'))
    if not 1 <= port <= 65535:
        raise SystemExit('Port invalide.')
    service = Server(('0.0.0.0', port))
    def cleanup():
        while True:
            time.sleep(5)
            with service.store.lock:
                service.store.purge()
    threading.Thread(target=cleanup, daemon=True).start()
    print('Extra Work — relais démarré derrière le proxy HTTPS Render.', flush=True)
    try:
        service.serve_forever()
    finally:
        service.server_close()

if __name__ == '__main__':
    main()
