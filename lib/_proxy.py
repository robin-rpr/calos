import socket
import threading


## Classes ##

class Proxy:
    def __init__(self, target_host, target_port, listen_host, listen_port):
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.thread = None
        self.socket = None

    def __repr__(self):
        if self.socket:
            return str(self.socket.getsockname()[1])
        return str(self.listen[1])

    def start(self):
        if self.thread is not None:
            return
        
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def stop(self):
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join(timeout=1)

    def _listen(self):
        self.socket = socket.socket()
        self.socket.bind(self.listen)
        self.socket.listen()
        while True:
            try:
                client, _ = self.socket.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except (OSError, ConnectionError):
                break  # Socket was closed

    def _handle(self, client_sock):
        try:
            backend = socket.create_connection(self.target)
            threading.Thread(target=self._pipe, args=(client_sock, backend)).start()
            threading.Thread(target=self._pipe, args=(backend, client_sock)).start()
        except: 
            client_sock.close()

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