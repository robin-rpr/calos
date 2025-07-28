#!/usr/bin/env python3

import sys
import os
import logging
import subprocess
import uuid
from time import sleep

try:
    # Cython provides PKGLIBDIR.
    sys.path.insert(0, PKGLIBDIR)
except NameError:
    # Extend sys.path to include the parent directory. This is necessary because this
    # script resides in a subdirectory, and we need to import shared modules located
    # in the project's top-level 'lib' directory.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

import _executor as _executor
import _zeroconf as _zeroconf
from _http import WebServer


## Constants ##

try:
    # Cython provides PKGDATADIR.
    STATIC_DIR = PKGDATADIR
    TEMPLATE_DIR = os.path.join(PKGDATADIR, 'templates')
except NameError:
    # Define STATIC_DIR to be the static directory relative to the current file.
    STATIC_DIR = os.path.join(os.path.dirname(__file__), '..', 'static')
    TEMPLATE_DIR = os.path.join(STATIC_DIR, 'templates')

# Executors
# The C-based executor is being phased out for container operations
# in favor of calling the clearly CLI.
executor = _executor.Executor()
studio_executor = _executor.StudioExecutor()

# Zeroconf
zeroconf = _zeroconf.Zeroconf()

# Server
server = WebServer(
    host='0.0.0.0',
    port=8080,
    static_dir=STATIC_DIR,
    template_dir=TEMPLATE_DIR,
)

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


## Routes ##

@server.get('/api/containers')
def list_containers(payload=None):
    """List all containers."""
    return executor.list_containers()

@server.get('/api/containers/<container_id>')
def get_container(container_id, payload=None):
    """Get container details by ID."""
    return executor.get_container(container_id)

@server.get('/api/containers/<container_id>/logs')
def get_container_logs(container_id, payload=None):
    """Get container logs by ID."""
    return executor.get_container_logs(container_id)

@server.post('/api/containers')
def start_container(payload):
    """Start a new container."""
    return executor.start_container(
        payload.get('name', str(uuid.uuid4())[:8]),
        payload.get('image', 'ubuntu:latest'),
        payload.get('command', []),
        payload.get('publish', {}),
        payload.get('environment', {})
    )

@server.delete('/api/containers/<container_id>')
def stop_container(container_id, payload=None):
    """Stop a container by ID."""
    try:
        subprocess.run(['clearly', 'stop', container_id], capture_output=True, text=True, check=True)
        return {'status': 'stopped', 'id': container_id}
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to stop container {container_id}: {e.stderr}")
        raise Exception(f"Error stopping container: {e.stderr}")

@server.get('/api/studios')
def list_studios(payload=None):
    """List all studios."""
    return studio_executor.list_studios()

@server.get('/api/studios/<studio_id>')
def get_studio(studio_id, payload=None):
    """Get studio details by ID."""
    return studio_executor.get_studio(studio_id)

@server.get('/api/studios/<studio_id>/logs')
def get_studio_logs(studio_id, payload=None):
    """Get studio logs by ID."""
    return studio_executor.get_studio_logs(studio_id)

@server.post('/api/studios')
def start_studio(payload):
    """Start a new studio."""
    name = payload.get('name', str(uuid.uuid4())[:8])
    return studio_executor.start_studio(name)

@server.delete('/api/studios/<studio_id>')
def stop_studio(studio_id, payload=None):
    """Stop a studio by ID."""
    return studio_executor.stop_studio(studio_id)


## Pages ##

@server.get('/')
def serve_index(payload=None):
    """Serve the main index page."""
    template = server.jinja_env.get_template('pages/index.html')
    html = template.render()
    return {'type': 'text/html', 'content': html}

@server.get('/studio/<studio_id>')
def serve_studio(studio_id, payload=None):
    """Serve a studio page by ID."""
    template = server.jinja_env.get_template('pages/studio.html')
    html = template.render(id=studio_id)
    return {'type': 'text/html', 'content': html}


## Main ##

def main():
    try:
        logger.info(f"Listening on http://{server.host}:{server.port}")
        server.start()

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()