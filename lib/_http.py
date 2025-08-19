from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Callable, Dict, List, Tuple, Any, Optional
from jinja2 import Environment, FileSystemLoader
import threading
import mimetypes
import logging
import json
import sass
import sys
import os
import re
import subprocess
import uuid
import functools
import logging


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
                 static_dir: str = 'static', template_dir: str = 'pages'):
        """
        Initialize the WebServer.
        
        Args:
            host: Server host address
            port: Server port
            static_dir: Directory for static files
            template_dir: Directory for Jinja2 templates
        """
        self.host = host
        self.port = port
        self.static_dir = static_dir
        self.template_dir = template_dir
        self.routes: Dict[str, Dict[str, Callable]] = {}
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    
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
    
    def put(self, path: str):
        """Decorator for PUT routes."""
        return self.route(path, ['PUT'])
    
    def patch(self, path: str):
        """Decorator for PATCH routes."""
        return self.route(path, ['PATCH'])
    
    def _match_route(self, path: str, method: str) -> Tuple[Optional[Callable], Dict[str, str]]:
        """Match a request path and method to a registered route."""
        # First try exact match
        if path in self.routes and method in self.routes[path]:
            return self.routes[path][method], {}
        
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
            match = re.match(pattern, path)
            
            if match:
                # Extract path parameters using named parameters
                params = {}
                for i, param_name in enumerate(param_names):
                    if i < len(match.groups()):
                        params[param_name] = match.group(i + 1)
                
                return handler, params
        
        return None, {}
    
    def _handler_class(self):
        """Create the HTTP handler class with all registered routes."""
        
        class HTTPHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle_request('GET')
            
            def do_POST(self):
                self._handle_request('POST')
            
            def do_DELETE(self):
                self._handle_request('DELETE')
            
            def _handle_request(self, method):
                try:
                    # Handle special routes first
                    if self.path == '/main.css':
                        self._serve_css()
                        return
                    elif self.path.startswith('/static/'):
                        self._serve_static()
                        return
                    
                    # Match route
                    handler, params = self.server._match_route(self.path, method)
                    
                    if handler:
                        # Parse request body for POST/DELETE
                        payload = {}
                        if method in ['POST', 'DELETE']:
                            content_length = int(self.headers.get('Content-Length', 0))
                            if content_length:
                                body = self.rfile.read(content_length).decode('utf-8')
                                payload = json.loads(body) if body.strip() else {}
                        
                        # Call handler with parameters
                        if params:
                            result = handler(**params, payload=payload)
                        else:
                            result = handler(payload=payload)
                        
                        if result is not None:
                            if isinstance(result, dict) and result.get('type') == 'text/html':
                                # Serve HTML response
                                self.send_response(200)
                                self.send_header('Content-type', 'text/html; charset=utf-8')
                                self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
                                self.end_headers()
                                self.wfile.write(result['content'].encode('utf-8'))
                            else:
                                # Serve JSON response
                                self._send_json(result)
                    else:
                        self.send_error(404, "Not Found")
                        
                except Exception as e:
                    logger.error(f"Error handling {method} request {self.path}: {e}", exc_info=True)
                    self.send_error(500, "Internal Server Error")
            
            def _serve_css(self):
                """Compile and serve SCSS to CSS."""
                styles = sass.compile(filename=os.path.join(self.server.static_dir, 'styles', 'main.scss'))
                
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
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
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            
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

        threading.Thread(target=server.serve_forever, daemon=True).start()