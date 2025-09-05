import time
import socket
import threading
import re


## Classes ##

class Proxy:
    def __init__(self, target_host, target_port, listen_host, listen_port):
        self.listen = (listen_host, listen_port)
        self.target = (target_host, target_port)
        self.thread = None
        self.socket = None

    def start(self):
        if self.thread is not None:
            return

        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

        while self.socket is None:
            time.sleep(0.1)

    def stop(self):
        if self.socket:
            self.socket.close()
        if self.thread:
            self.thread.join(timeout=1)

    def _handle(self, client_sock):
        try:
            backend = socket.create_connection(self.target)
            threading.Thread(target=self._pipe, args=(client_sock, backend, False)).start()
            threading.Thread(target=self._pipe, args=(backend, client_sock, True)).start()
        except: 
            client_sock.close()

    def _add_cors_header(self, data):
        try:
            response = data.decode('utf-8', errors='ignore')
            if not response.startswith('HTTP/'):
                return data
            
            header_end = response.find('\r\n\r\n')
            if header_end == -1:
                return data
            
            headers = response[:header_end]
            body = response[header_end + 4:]
            
            # Add or replace CORS header
            if 'Access-Control-Allow-Origin:' in headers:
                headers = re.sub(r'Access-Control-Allow-Origin: [^\r\n]*', 'Access-Control-Allow-Origin: *', headers)
            else:
                headers += '\r\nAccess-Control-Allow-Origin: *'
            
            return (headers + '\r\n\r\n' + body).encode('utf-8')
        except:
            return data

    def _listen(self):
        self.socket = socket.socket()
        self.socket.bind(self.listen)
        self.socket.listen()

        while True:
            try:
                client, _ = self.socket.accept()
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
            except (OSError, ConnectionError):
                break # Socket was closed

        try:
            self.socket.close()
        except Exception:
            pass

    def _pipe(self, src, dst, is_response):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                
                if is_response:
                    data = self._add_cors_header(data)
                
                dst.sendall(data)
        except:
            pass
        finally:
            src.close(); dst.close()