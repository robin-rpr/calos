from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Callable, Dict, List, Tuple, Any, Optional
from jinja2 import Environment, FileSystemLoader
import urllib.parse
import subprocess
import threading
import mimetypes
import functools
import logging
import hashlib
import socket
import base64
import struct
import json
import sass
import yaml
import sys
import os
import re


## Constants ##

CACHE_MAX_AGE = 86400 # 24 hours
logger = logging.getLogger(__name__)


## Classes ##

class WebServer:
    """
    A clean, modern HTTP server with decorator-based routing.
    
    Example:
        server = WebServer(host='127.0.0.1', port=8080)
        
        @server.get('/api/users/<user_id>')
        def get_user(self, user_id, payload=None):
            return {'user_id': user_id}
        
        server.start()
    """
    
    def __init__(self, host: str = '127.0.0.1', port: int = 8080, 
                 static_dir: str = 'data', template_dir: str = 'pages',
                 headers: Dict[str, str] = None):
        """
        Initialize the WebServer.
        
        Args:
            host: Server host address
            port: Server port
            static_dir: Directory for static files
            template_dir: Directory for Jinja2 templates
            headers: Custom headers to add to all responses
        """
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.template_dir = template_dir
        self.routes: Dict[str, Dict[str, Callable]] = {}
        self.routes_websocket: Dict[str, Callable] = {}
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        
        # Custom rewrite records.
        self.records: Dict[str, dict] = {}
        
        # Custom headers.
        self.headers = {}
        if headers:
            self.headers.update(headers)
    
    def route(self, path: str, methods: List[str] = None):
        """Decorator to register a route handler directly on the server."""
        if methods is None:
            methods = ['GET']
        
        def decorator(func: Callable) -> Callable:
            # Extract parameter names from path
            route_params = []
            for part in path.split('/'):
                if part.startswith('<') and part.endswith('>'):
                    route_params.append(part[1:-1])  # Remove < and >
            
            # Store route metadata
            func._route_path = path
            func._route_methods = methods
            func._route_params = route_params
            
            # Register the route
            if path not in self.routes:
                self.routes[path] = {}
            
            for method in methods:
                self.routes[path][method] = func
            
            return func
        return decorator
    
    def get(self, path: str):
        """Decorator for GET routes."""
        return self.route(path, ['GET'])
    
    def post(self, path: str):
        """Decorator for POST routes."""
        return self.route(path, ['POST'])
    
    def delete(self, path: str):
        """Decorator for DELETE routes."""
        return self.route(path, ['DELETE'])
    
    def websocket(self, path: str):
        """Decorator for WebSocket routes."""
        def decorator(func):
            self.routes_websocket[path] = func
            return func
        return decorator
    
    def put(self, path: str):
        """Decorator for PUT routes."""
        return self.route(path, ['PUT'])
    
    def patch(self, path: str):
        """Decorator for PATCH routes."""
        return self.route(path, ['PATCH'])
    
    def insert(self, path: str, port: int, host: str = "127.0.0.1"):
        """Add a record for rewriting."""
        self.records[path] = {
            "path": path,
            "port": port,
            "host": host
        }
    
    def lookup(self, path: str) -> Optional[dict]:
        """Find the record for a given path."""
        for record in self.records.values():
            if path.startswith(record["path"]):
                return record
        return None

    def drop(self, path: str):
        """Remove a record."""
        self.records.pop(path)
    
    def _match_route(self, path: str, method: str) -> Tuple[Optional[Callable], Dict[str, str]]:
        """Match a request path and method to a registered route."""
        # Split path and query parameters
        path_parts = path.split('?', 1)
        base_path = path_parts[0]
        query_string = path_parts[1] if len(path_parts) > 1 else ""
        
        # Parse query parameters
        query_params = {}
        if query_string:
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    query_params[key] = value
        
        # First try exact match
        if base_path in self.routes and method in self.routes[base_path]:
            return self.routes[base_path][method], query_params
        
        # Then try pattern matching
        for route_path, route_handlers in self.routes.items():
            if method not in route_handlers:
                continue
            
            handler = route_handlers[method]
            if not hasattr(handler, '_route_params'):
                continue
                
            # Convert Flask-style route to regex pattern
            pattern_parts = []
            param_names = []
            
            for part in route_path.split('/'):
                if part.startswith('<') and part.endswith('>'):
                    param_name = part[1:-1]  # Remove < and >
                    pattern_parts.append('([^/]+)')
                    param_names.append(param_name)
                else:
                    pattern_parts.append(re.escape(part))
            
            pattern = '^' + '/'.join(pattern_parts) + '$'
            match = re.match(pattern, base_path)
            
            if match:
                # Extract path parameters using named parameters
                params = query_params.copy()  # Start with query params
                for i, param_name in enumerate(param_names):
                    if i < len(match.groups()):
                        params[param_name] = match.group(i + 1)
                
                return handler, params
        
        return None, {}
    
    def _match_route_websocket(self, path):
        """Match WebSocket route and extract parameters."""
        import re
        
        for route_path, handler in self.routes_websocket.items():
            # Convert route pattern to regex (same logic as HTTP routes)
            pattern = route_path
            param_names = []
            
            # Find all <param> patterns
            param_matches = re.findall(r'<([^>]+)>', pattern)
            for param_name in param_matches:
                param_names.append(param_name)
                pattern = pattern.replace(f'<{param_name}>', '([^/]+)')
            
            # Match the pattern
            match = re.match(f'^{pattern}$', path)
            if match:
                # Extract path parameters
                params = {}
                for i, param_name in enumerate(param_names):
                    if i < len(match.groups()):
                        params[param_name] = match.group(i + 1)
                
                return handler, params
        
        return None, {}
    
    def _send_headers(self, handler):
        """Send custom headers."""
        for name, value in self.headers.items():
            handler.send_header(name, value)
    
    def _handler_class(self):
        """Create the HTTP handler class with all registered routes."""
        
        class SocketHandler:            
            def __init__(self, client_socket, target_host, target_port, path):
                self.client_socket = client_socket
                self.target_host = target_host
                self.target_port = target_port
                self.path = path
                self.target_socket = None
                self.running = False
            
            def handle_websocket(self, client_handshake: str):
                """Proxy WebSocket by forwarding the client's handshake to the target,
                relaying the 101 response, then tunneling frames in both directions."""
                try:
                    # Connect to target
                    self.target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.target_socket.settimeout(30)
                    self.target_socket.connect((self.target_host, self.target_port))
                    
                    # Forward the client's handshake to the target
                    self.target_socket.sendall(client_handshake.encode('utf-8'))
                    
                    # Read target response headers (until CRLF CRLF)
                    response_data = b""
                    while b"\r\n\r\n" not in response_data:
                        chunk = self.target_socket.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                    
                    if not response_data:
                        return
                    
                    # Relay the response (including any extra bytes already read)
                    self.client_socket.sendall(response_data)
                    
                    # Start bidirectional forwarding
                    self.running = True
                    client_thread = threading.Thread(target=self._forward_to_target, daemon=True)
                    target_thread = threading.Thread(target=self._forward_to_client, daemon=True)
                    
                    client_thread.start()
                    target_thread.start()
                    
                    # Wait for threads to complete
                    client_thread.join()
                    target_thread.join()
                    
                except Exception as e:
                    logger.error(f"WebSocket error: {e}")
                finally:
                    self.cleanup()
            
            def _forward_to_target(self):
                """Forward data from client to target"""
                try:
                    while self.running:
                        data = self.client_socket.recv(4096)
                        if not data:
                            break
                        if self.target_socket:
                            self.target_socket.send(data)
                except:
                    pass
                finally:
                    self.running = False
            
            def _forward_to_client(self):
                """Forward data from target to client"""
                try:
                    while self.running:
                        if self.target_socket:
                            data = self.target_socket.recv(4096)
                            if not data:
                                break
                            self.client_socket.send(data)
                except:
                    pass
                finally:
                    self.running = False
            
            def cleanup(self):
                """Clean up connections"""
                self.running = False
                if self.client_socket:
                    self.client_socket.close()
                if self.target_socket:
                    self.target_socket.close()
        
        class HTTPHandler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_GET(self):
                if self.headers.get('Upgrade') == 'websocket':
                    self._handle_websocket()
                else:
                    self._handle_request('GET')
            
            def do_POST(self):
                self._handle_request('POST')
            
            def do_DELETE(self):
                self._handle_request('DELETE')
            
            def do_PUT(self):
                self._handle_request('PUT')
            
            def do_PATCH(self):
                self._handle_request('PATCH')
            
            def do_OPTIONS(self):
                self.send_response(200)
                self.server.webserver._send_headers(self)
                self.send_header('Content-Length', '0')
                self.end_headers()
            
            def _handle_request(self, method):
                try:
                    # Match static.
                    if self.path == '/main.css':
                        self._serve_css()
                        return
                    elif self.path.startswith('/static/'):
                        self._serve_static()
                        return
                    
                    # Match lookup.
                    record = self.server.webserver.lookup(self.path)
                    if record:
                        self._handle_rewrite_request(record, method)
                        return
                    
                    # Match route.
                    handler, params = self.server._match_route(self.path, method)
                    
                    if handler:
                        # Parse request body for POST/DELETE.
                        payload = {}
                        if method in ['POST', 'DELETE']:
                            content_length = int(self.headers.get('Content-Length', 0))
                            if content_length:
                                body = self.rfile.read(content_length).decode('utf-8')
                                if body.strip():
                                    content_type = self.headers.get('Content-Type', '')
                                    if 'application/x-yaml' in content_type or 'text/yaml' in content_type:
                                        # Handle YAML content.
                                        payload = yaml.safe_load(body)
                                    else:
                                        # Default to JSON.
                                        payload = json.loads(body)
                        
                        # Call handler with parameters
                        if params:
                            result = handler(**params, payload=payload)
                        else:
                            result = handler(payload=payload)
                        
                        if result is not None:
                            if isinstance(result, dict) and result.get('type') == 'text/html':
                                # Serve HTML response
                                body_bytes = result['content'].encode('utf-8')
                                self.send_response(200)
                                self.send_header('Content-type', 'text/html; charset=utf-8')
                                self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
                                self.send_header('Content-Length', str(len(body_bytes)))
                                self.server.webserver._send_headers(self)
                                self.end_headers()
                                self.wfile.write(body_bytes)
                            else:
                                # Serve JSON response
                                self._send_json(result)
                    else:
                        self.send_error(404, "Not Found")
                        
                except Exception as e:
                    logger.error(f"Error handling {method} request {self.path}: {e}", exc_info=True)
                    self.send_error(500, "Internal Server Error")
            
            def _handle_websocket(self):
                try:
                    # Match lookup
                    record = self.server.webserver.lookup(self.path)
                    if record:
                        self._handle_rewrite_websocket(record)
                        return
                    
                    # Match route
                    handler, params = self.server._match_route_websocket(self.path)
                    
                    if not handler:
                        self.send_error(404, "WebSocket route not found")
                        return
                    
                    # Perform WebSocket handshake
                    key = self.headers.get('Sec-WebSocket-Key')
                    if not key:
                        self.send_error(400, "Missing Sec-WebSocket-Key")
                        return False
                    
                    # Generate accept key
                    accept_key = base64.b64encode(
                        hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
                    ).decode()
                    
                    # Send upgrade response
                    self.send_response(101, 'Switching Protocols')
                    self.send_header('Upgrade', 'websocket')
                    self.send_header('Connection', 'Upgrade')
                    self.send_header('Sec-WebSocket-Accept', accept_key)
                    self.server.webserver._send_headers(self)
                    self.end_headers()
                
                    # Call the WebSocket handler with parameters
                    handler(self, **params)
                    
                except Exception as e:
                    logger.error(f"WebSocket error: {e}")
                    self.send_error(500, "WebSocket error")
            
            def _handle_rewrite_websocket(self, record: dict):
                """Handle WebSocket rewrite connection"""
                try:
                    # Rewrite the path
                    rewritten_path = self._rewrite_path(record, self.path)
                    
                    # Reconstruct client's WebSocket handshake with rewritten path
                    request_version = getattr(self, 'request_version', 'HTTP/1.1')
                    handshake_lines = [f"GET {rewritten_path} {request_version}"]
                    
                    # Use target host in Host header
                    handshake_lines.append(f"Host: {record['host']}:{record['port']}")
                    
                    # Forward other headers from the client, except ones we override
                    for header_name, header_value in self.headers.items():
                        lower = header_name.lower()
                        if lower in ['host']:
                            continue
                        if lower in ['content-length', 'transfer-encoding']:
                            continue
                        handshake_lines.append(f"{header_name}: {header_value}")
                    
                    # Optional forwarded headers
                    try:
                        client_ip = self.client_address[0]
                        original_host = self.headers.get('Host', 'localhost')
                        handshake_lines.append(f"X-Forwarded-For: {client_ip}")
                        handshake_lines.append(f"X-Real-IP: {client_ip}")
                        handshake_lines.append(f"X-Forwarded-Host: {original_host}")
                        handshake_lines.append(f"X-Forwarded-Server: {original_host}")
                    except Exception:
                        pass
                    
                    handshake = "\r\n".join(handshake_lines) + "\r\n\r\n"
                    
                    # Create WebSocket handler
                    ws_handler = SocketHandler(
                        self.connection,
                        record["host"],
                        record["port"],
                        rewritten_path
                    )
                    
                    # Handle WebSocket in a separate thread and keep this handler alive
                    ws_thread = threading.Thread(target=ws_handler.handle_websocket, args=(handshake,), daemon=False)
                    ws_thread.start()
                    ws_thread.join()
                    
                except Exception as e:
                    logger.error(f"Proxy WebSocket error: {e}")
                    self.send_error(500, "Proxy WebSocket error")
            
            def _rewrite_path(self, record: dict, original_path: str) -> str:
                """Rewrite the path by removing the rewrite prefix"""
                if original_path.startswith(record["path"]):
                    rewritten_path = original_path[len(record["path"]):]
                    if not rewritten_path.startswith('/'):
                        rewritten_path = '/' + rewritten_path
                    return rewritten_path
                return original_path
            
            def _handle_rewrite_request(self, record: dict, method: str):
                """Handle rewrite request to target rewrite."""
                try:
                    # Rewrite the path
                    rewritten_path = self._rewrite_path(record, self.path)
                    
                    # Build target URL
                    target_url = f"http://{record['host']}:{record['port']}{rewritten_path}"
                    if self.path.find('?') >= 0:
                        target_url += self.path[self.path.find('?'):]
                    
                    # Parse the target URL
                    parsed_url = urllib.parse.urlparse(target_url)
                    
                    # Create connection to target
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_socket.settimeout(30)
                    target_socket.connect((record["host"], record["port"]))
                    
                    # Build HTTP request
                    request_line = f"{method} {parsed_url.path}"
                    if parsed_url.query:
                        request_line += f"?{parsed_url.query}"
                    request_line += f" HTTP/1.1\r\n"
                    
                    # Build headers
                    headers = []
                    headers.append(f"Host: {record['host']}:{record['port']}")

                    # Add forwarded headers for rewrite context
                    headers.append(f"X-Forwarded-Host: {self.headers.get('Host', 'localhost')}")
                    headers.append(f"X-Forwarded-Server: {self.headers.get('Host', 'localhost')}")
                    headers.append(f"X-Forwarded-For: {self.client_address[0]}")
                    headers.append(f"X-Real-IP: {self.client_address[0]}")
                    
                    # Copy relevant headers
                    for header_name, header_value in self.headers.items():
                        if header_name.lower() not in ['host', 'connection']:
                            headers.append(f"{header_name}: {header_value}")
                    
                    headers.append("Connection: close")
                    
                    # Send request
                    request_data = request_line + "\r\n".join(headers) + "\r\n\r\n"
                    if hasattr(self, 'rfile') and method in ['POST', 'PUT', 'PATCH']:
                        content_length = int(self.headers.get('Content-Length', 0))
                        if content_length > 0:
                            body = self.rfile.read(content_length)
                            request_data += body.decode('utf-8', errors='ignore')
                    
                    target_socket.sendall(request_data.encode('utf-8'))
                    
                    # Read response
                    response_data = b""
                    while True:
                        try:
                            chunk = target_socket.recv(4096)
                            if not chunk:
                                break
                            response_data += chunk
                        except socket.timeout:
                            break
                    
                    target_socket.close()
                    
                    # Parse and forward response
                    self._parse_and_forward_response(response_data)
                    
                except Exception as e:
                    logger.error(f"Error forwarding request: {e}")
                    self.send_error(502, "Bad Gateway")
            
            def _parse_and_forward_response(self, response_data: bytes):
                """Parse the response and forward it to the client"""
                try:
                    # Split response into headers and body
                    response_str = response_data.decode('utf-8', errors='ignore')
                    header_end = response_str.find('\r\n\r\n')
                    
                    if header_end == -1:
                        self.send_error(502, "Invalid response from target")
                        return
                    
                    headers_str = response_str[:header_end]
                    body = response_data[header_end + 4:]
                    
                    # Parse status line
                    lines = headers_str.split('\r\n')
                    status_line = lines[0]
                    status_parts = status_line.split(' ', 2)
                    
                    if len(status_parts) < 2:
                        self.send_error(502, "Invalid status line")
                        return
                    
                    status_code = int(status_parts[1])
                    
                    # Parse headers
                    response_headers = {}
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            response_headers[key.strip()] = value.strip()

                    # Determine transfer encoding
                    te_value = None
                    for k, v in response_headers.items():
                        if k.lower() == 'transfer-encoding':
                            te_value = v
                            break
                    is_chunked = te_value is not None and ('chunked' in te_value.lower())

                    # Send status
                    self.send_response(status_code)

                    # Send headers (preserve TE when chunked, drop conflicting ones)
                    has_content_length = False
                    for key, value in response_headers.items():
                        lower_key = key.lower()
                        if lower_key == 'connection':
                            continue
                        if lower_key == 'content-length':
                            has_content_length = True
                            if is_chunked:
                                # Do not send Content-Length with chunked TE
                                continue
                            # Otherwise, forward as-is
                            self.send_header(key, value)
                            continue
                        if lower_key == 'transfer-encoding':
                            # Preserve TE header; client will decode chunked body correctly
                            self.send_header(key, value)
                            continue
                        self.send_header(key, value)

                    # If not chunked and no Content-Length provided, add it
                    if not is_chunked and not has_content_length:
                        self.send_header('Content-Length', str(len(body or b'')))

                    self.end_headers()

                    # Send body
                    if body:
                        self.wfile.write(body)
                        
                except Exception as e:
                    logger.error(f"Error parsing response: {e}")
                    self.send_error(502, "Error parsing response")
            
            def _serve_css(self):
                """Compile and serve SCSS to CSS."""
                styles = sass.compile(filename=os.path.join(self.server.static_dir, 'styles', 'main.scss'))
                
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
                self.send_header('Content-Length', str(len(styles.encode('utf-8'))))
                self.server.webserver._send_headers(self)
                self.end_headers()
                self.wfile.write(styles.encode('utf-8'))
            
            def _serve_static(self):
                """Serve static files securely."""
                rel_path = self.path.removeprefix("/static/").replace("\\", "/")
                full_path = os.path.abspath(os.path.join(self.server.static_dir, rel_path))

                if not full_path.startswith(os.path.abspath(self.server.static_dir)):
                    self.send_error(403, "Forbidden")
                    return

                if os.path.isfile(full_path):
                    try:
                        with open(full_path, 'rb') as f:
                            mimetype, _ = mimetypes.guess_type(full_path)
                            self.send_response(200)
                            self.send_header('Content-type', mimetype or 'application/octet-stream')
                            self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
                            # Compute length without reading file twice
                            try:
                                file_size = os.path.getsize(full_path)
                                self.send_header('Content-Length', str(file_size))
                            except Exception:
                                pass
                            self.server.webserver._send_headers(self)
                            self.end_headers()
                            self.wfile.write(f.read())
                    except IOError:
                        self.send_error(500, "Error reading file")
                else:
                    self.send_error(404, "Static file not found")
            
            def _send_json(self, data, status_code=200):
                """Send JSON response."""
                response = json.dumps(data, indent=2, default=str)
                self.send_response(status_code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.server.webserver._send_headers(self)
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            
            def _send_message(self, message):
                """Send a WebSocket message."""
                try:
                    if isinstance(message, str):
                        message = message.encode('utf-8')
                    
                    # Simple WebSocket frame (text message, no masking)
                    header = struct.pack('!BB', 0x81, len(message))
                    self.connection.send(header + message)
                except:
                    pass
            
            def _receive_message(self):
                """Receive a WebSocket message."""
                try:
                    # Read frame header
                    header = self.connection.recv(2)
                    if len(header) < 2:
                        return None
                    
                    opcode = header[0] & 0x0F
                    if opcode == 0x8:  # Close frame
                        return None
                    
                    payload_len = header[1] & 0x7F
                    if payload_len == 126:
                        payload_len = struct.unpack('!H', self.connection.recv(2))[0]
                    elif payload_len == 127:
                        payload_len = struct.unpack('!Q', self.connection.recv(8))[0]
                    
                    # Skip mask if present (client messages are masked)
                    if header[1] & 0x80:
                        self.connection.recv(4)  # Skip mask
                    
                    payload = self.connection.recv(payload_len)
                    return payload.decode('utf-8') if payload else None
                except:
                    return None
            
            def log_message(self, format, *args):
                """Redirect server logging to the main logger."""
                logger.info(f"{self.address_string()} - {args[0]} {args[1]}")
        
        return HTTPHandler
    
    def start(self):
        """Start the server."""
        handler_class = self._handler_class()
        server = ThreadingHTTPServer((self.host, self.port), handler_class)
        server.static_dir = self.static_dir
        server.template_dir = self.template_dir
        server._match_route = self._match_route
        server._match_route_websocket = self._match_route_websocket
        server.lookup = self.lookup
        server.webserver = self

        threading.Thread(target=server.serve_forever, daemon=True).start()