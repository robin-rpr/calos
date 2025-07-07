#!/usr/bin/env python3

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from jinja2 import Environment, FileSystemLoader
import mimetypes
import logging
import signal
import json
import sass
import sys
import os
import re

try:
    # Cython provides PKGLIBDIR.
    sys.path.insert(0, PKGLIBDIR)
except NameError:
    # Extend sys.path to include the parent directory. This is necessary because this
    # script resides in a subdirectory, and we need to import shared modules located
    # in the project's top-level 'lib' directory.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

import _executor as _executor


## Constants ##

try:
    # Cython provides PKGDATADIR.
    STATIC_DIR = PKGDATADIR
    TEMPLATE_DIR = os.path.join(PKGDATADIR, 'templates')
except NameError:
    # Define STATIC_DIR to be the static directory relative to the current file.
    STATIC_DIR = os.path.join(os.path.dirname(__file__), '..', 'static')
    TEMPLATE_DIR = os.path.join(STATIC_DIR, 'templates')

# Caching
CACHE_MAX_AGE = 86400 # 24 hours

# Executors
executor = _executor.Executor()
studio_executor = _executor.StudioExecutor()

# Jinja2 Environment
jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/clearly.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


## Classes ##

class HTTPHandler(BaseHTTPRequestHandler):
    """A HTTP request handler."""

    def do_GET(self):
        """Handle GET requests."""
        try:
            if self.path == '/':
                self.serve_index()
            elif self.path == '/main.css':
                self.serve_scss()
            elif self.path.startswith('/api/'):
                self.serve_api('GET')
            elif self.path.startswith('/static/'):
                self.serve_file()
            else:
                self.send_error(404, "File Not Found")
        except Exception as e:
            logger.error(f"Error handling request for {self.path}: {e}", exc_info=True)
            self.send_error(500, "Internal Server Error")

    def do_POST(self):
        """Handle POST requests."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Read the request body.
            if content_length:
                body = self.rfile.read(content_length).decode('utf-8')
                payload = json.loads(body) if body.strip() else {}
            else:
                payload = {}
                
            self.serve_api('POST', payload)
        except Exception as e:
            logger.error(f"Error handling request for {self.path}: {e}", exc_info=True)
            self.send_error(500, "Internal Server Error")

    def do_DELETE(self):
        """Handle DELETE requests."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Read the request body.
            if content_length:
                body = self.rfile.read(content_length).decode('utf-8')
                payload = json.loads(body) if body.strip() else {}
            else:
                payload = {}
                
            self.serve_api('DELETE', payload)
        except Exception as e:
            logger.error(f"Error handling request for {self.path}: {e}", exc_info=True)
            self.send_error(500, "Internal Server Error")

    def serve_index(self):
        """Serves the index.html page."""
        template = jinja_env.get_template('pages/index.html')
        example = "Example5"
        html_content = template.render(example=example)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def serve_scss(self):
        """Compiles SCSS to CSS."""
        styles = sass.compile(filename=os.path.join(STATIC_DIR, 'styles', 'main.scss'))
        
        self.send_response(200)
        self.send_header('Content-type', 'text/css')
        self.send_header('Cache-Control', f'public, max-age={CACHE_MAX_AGE}')
        self.end_headers()
        self.wfile.write(styles.encode('utf-8'))

    def serve_api(self, method, payload={}):
        """Serves REST API requests."""
        if method == 'GET':
            # GET
            if self.path == '/api/containers':
                return self.send_json(executor.list_containers())
            elif re.fullmatch(r'/api/containers/[^/]+', self.path):
                id = self.path.split('/')[-1]
                return self.send_json(executor.get_container(id))
            elif re.fullmatch(r'/api/containers/[^/]+/logs', self.path):
                id = self.path.split('/')[-2]
                print(id)
                return self.send_json(executor.get_container_logs(id))
            elif self.path == '/api/studios':
                return self.send_json(studio_executor.list_studios())
            elif re.fullmatch(r'/api/studios/[^/]+', self.path):
                id = self.path.split('/')[-1]
                return self.send_json(studio_executor.get_studio(id))
            elif re.fullmatch(r'/api/studios/[^/]+/logs', self.path):
                id = self.path.split('/')[-2]
                return self.send_json(studio_executor.get_studio_logs(id))
        elif method == 'POST':
            # POST
            if self.path == '/api/containers':
                id = payload.get('id', None)
                image = payload.get('image', 'ubuntu:latest')
                command = payload.get('command', [])
                publish = payload.get('publish', {})
                environment = payload.get('environment', {})

                return self.send_json(executor.start_container(id, image, command, publish, environment))
            elif self.path == '/api/studios':
                id = payload.get('id', None)
                logger.info(f"Starting studio {id}")
                containers = [
                    {
                        "id": "vscode",
                        "image": "codercom/code-server:4.101.2-39",
                        "command": ["/usr/bin/entrypoint.sh", "--bind-addr", "0.0.0.0:8080", ".", "--auth", "none"],
                        "publish": { "9191": 8080 },
                        "environment": {
                            "ENTRYPOINTD": "/entrypoint.d"
                        }
                    }
                ]
                return self.send_json(studio_executor.start_studio(id, containers))
        elif method == 'DELETE':
            # DELETE
            if re.fullmatch(r'/api/containers/[^/]+', self.path):
                id = self.path.split('/')[-1]
                return self.send_json(executor.stop_container(id))
        
        return self.send_error(404, "Not Found")

    def serve_file(self):
        """Serves static files securely."""
        rel_path = self.path.removeprefix("/static/").replace("\\", "/") # Normalization.
        full_path = os.path.abspath(os.path.join(STATIC_DIR, rel_path))

        if not full_path.startswith(os.path.abspath(STATIC_DIR)):
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
    
    def log_message(self, format, *args):
        """Redirect server logging to the main logger."""
        logger.info(f"{self.address_string()} - {args[0]} {args[1]}")

    def send_json(self, data):
        """Send JSON response"""
        response = json.dumps(data, indent=2)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

## Helpers ##

def signal_handler(signum, frame):
    """Handle Signals"""
    logger.info(f"SIGNAL: {signum}, Shutting down...")
    
    # Collect container and studio IDs for graceful shutdown
    # Release locks before stopping to prevent deadlocks
    container_ids = []
    studio_ids = []
    
    with executor.lock:
        container_ids = list(executor.containers.keys())
    
    with studio_executor.lock:
        studio_ids = list(studio_executor.studios.keys())
    
    # Stop all containers
    for id in container_ids:
        executor.stop_container(id)
    
    # Stop all studios
    for id in studio_ids:
        studio_executor.stop_studio(id)
    
    if 'server' in globals():
        server.server_close()
    sys.exit(0)


## Main ##

def main():
    global server
    try:
        # Register Signal Handlers
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Start Server
        host = '0.0.0.0'
        port = 8080
        server = ThreadingHTTPServer((host, port), HTTPHandler)
        logger.info(f"Listening on http://{host}:{port}")
        server.serve_forever()

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()