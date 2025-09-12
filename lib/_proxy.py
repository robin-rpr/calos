import time
import socket
import threading


## Classes ##

class Proxy:
    def __init__(self, target_host, target_port, listen_host, listen_port):
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.thread = None
        self.sock = None

    def __repr__(self):
        if self.sock:
            return str(self.sock.getsockname()[1])
        return str(self.listen[1])

    def start(self):
        if self.thread is not None:
            return

        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

        return

    def stop(self):
        if self.sock:
            self.sock.close()
        if self.thread:
            self.thread.join(timeout=1)

    def _listen(self):
        self.sock = socket.socket()
        self.sock.bind(self.listen)
        self.sock.listen()
        while True:
            try:
                client, _ = self.sock.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except (OSError, ConnectionError):
                # Socket was closed
                break

    def _handle(self, client_sock):
        try:
            backend = socket.create_connection(self.target)
            threading.Thread(target=self._pipe, args=(client_sock, backend)).start()
            threading.Thread(target=self._pipe, args=(backend, client_sock)).start()
        except: 
            client_sock.close()

    def _serve(self, timeout):
            self.sock = socket.socket()
            self.sock.bind(self.listen)
            self.sock.listen()
            self.sock.settimeout(1)
            while time.time() < timeout:
                try:
                    client, _ = self.sock.accept()
                    threading.Thread(target=self._handle, args=(client,), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
            try:
                self.sock.close()
            except Exception:
                pass

    def _pipe(self, src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except:
            pass
        finally:
            src.close(); dst.close()