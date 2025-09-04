import time
import socket
import threading


## Classes ##

class Proxy:
    def __init__(self, target_host, target_port, listen_host, listen_port):
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.thread = None
        self.socket = None

    def start(self, timeout=120):
        if self.thread is not None:
            return

        # Calculate timeout.
        timeout = time.time() + timeout

        self.thread = threading.Thread(target=self._listen, args=(timeout,), daemon=True)
        self.thread.start()

        while self.socket is None:
            time.sleep(0.1)

        return timeout

    def stop(self):
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join(timeout=1)

    def _handle(self, client_sock):
        try:
            backend = socket.create_connection(self.target)
            threading.Thread(target=self._pipe, args=(client_sock, backend)).start()
            threading.Thread(target=self._pipe, args=(backend, client_sock)).start()
        except: 
            client_sock.close()

    def _listen(self, timeout):
        self.socket = socket.socket()
        self.socket.bind(self.listen)
        self.socket.listen()

        while time.time() < timeout:
            try:
                client, _ = self.socket.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except (OSError, ConnectionError):
                break # Socket was closed

        try:
            self.socket.close()
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