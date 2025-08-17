#!/usr/bin/env python3

import sys
import os
import logging
import subprocess
import uuid
import time
import socket
import threading
import fcntl
import struct
import yaml
from time import sleep
from pathlib import Path

try:
    # Cython provides PKGLIBDIR.
    sys.path.insert(0, PKGLIBDIR)
except NameError:
    # Extend sys.path to include the parent directory. This is necessary because this
    # script resides in a subdirectory, and we need to import shared modules located
    # in the project's top-level 'lib' directory.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

import _runtime as _runtime
import _http as _http


## Constants ##

# Peer TTL for cluster discovery
PEER_TTL = 15.0

try:
    # Cython provides PKGDATADIR.
    STATIC_DIR = PKGDATADIR
    TEMPLATE_DIR = os.path.join(PKGDATADIR, 'templates')
except NameError:
    # Define STATIC_DIR to be the static directory relative to the current file.
    STATIC_DIR = os.path.join(os.path.dirname(__file__), '..', 'static')
    TEMPLATE_DIR = os.path.join(STATIC_DIR, 'templates')

# Runtime
runtime = _runtime.Runtime()

# Webserver
webserver = _http.WebServer(
    host='127.0.0.1',
    port=8080,
    static_dir=STATIC_DIR,
    template_dir=TEMPLATE_DIR,
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


## Routes ##

@webserver.post('/api/deploy')
def deploy(payload=None):
    """Deploy a new container."""
    try:
        document = yaml.safe_load(payload)
        identifier = uuid.uuid4().hex
        message = {
            "t": "DEPLOY", 
            "deploy": {
                "id": identifier,
                "services": document["services"]
            },
            "ts": time.time()
        }

        runtime.deploy(message)
        runtime.announce(message)

        return { "success": True, "id": identifier }
    except Exception as e:
        logger.error(f"Failed to deploy: {e}")
        return { "error": str(e) }

@webserver.get('/api/containers')
def list_containers(payload=None):
    """List all containers."""
    try:
        now = time.time();
        containers = {}
        with runtime.lock:
            for k, v in runtime.local_view.items():
                if v["status"] != "removed": 
                    container_info = {
                        "node": runtime.machine_id,
                        "status": v.get("status"),
                        "ip_address": v.get("ip_address", None),
                        "id": v.get("id", None)
                    }
                    containers[k] = container_info
            for nid, m in runtime.cluster.items():
                if now - m["ts"] > PEER_TTL: continue
                for k, v in m["containers"].items():
                    if v.get("status") != "removed":
                        container_info = {
                            "node": nid,
                            "status": v.get("status"),
                            "ip_address": v.get("ip_address", None),
                            "id": v.get("id", None)
                        }
                        containers.setdefault(k, container_info)

        return { "success": True, "containers": containers }
    except Exception as e:
        logger.error(f"Failed to list containers: {e}")
        return { "error": str(e) }

@webserver.get('/api/containers/<container_id>')
def get_container(container_id, payload=None):
    """Get container details by ID."""
    return runtime.get_container(container_id)

@webserver.get('/api/containers/<container_id>/logs')
def get_container_logs(container_id, payload=None):
    """Get container logs by ID."""
    return runtime.get_container_logs(container_id)

@webserver.post('/api/containers')
def start_container(payload):
    """Start a new container."""
    return runtime.start_container(
        payload.get('name', str(uuid.uuid4())[:8]),
        payload.get('image', 'ubuntu:latest'),
        payload.get('command', []),
        payload.get('publish', {}),
        payload.get('environment', {})
    )

@webserver.delete('/api/containers/<container_id>')
def stop_container(container_id, payload=None):
    """Stop a container by ID."""
    return runtime.stop_container(container_id)

# @webserver.get('/api/studios')
# def list_studios(payload=None):
#     """List all studios."""
#     return studio_executor.list_studios()
# 
# @webserver.get('/api/studios/<studio_id>')
# def get_studio(studio_id, payload=None):
#     """Get studio details by ID."""
#     return studio_executor.get_studio(studio_id)
# 
# @webserver.get('/api/studios/<studio_id>/logs')
# def get_studio_logs(studio_id, payload=None):
#     """Get studio logs by ID."""
#     return studio_executor.get_studio_logs(studio_id)
# 
# @webserver.post('/api/studios')
# def start_studio(payload):
#     """Start a new studio."""
#     name = payload.get('name', str(uuid.uuid4())[:8])
#     return studio_executor.start_studio(name)
# 
# @webserver.delete('/api/studios/<studio_id>')
# def stop_studio(studio_id, payload=None):
#     """Stop a studio by ID."""
#     return studio_executor.stop_studio(studio_id)
# 
# @webserver.get('/api/machines')
# def list_machines(payload=None):
#     """List all discovered Clearly machines."""
#     with listener.lock:
#         return listener.services.copy()


## Pages ##

@webserver.get('/')
def serve_index(payload=None):
    """Serve the main index page."""
    template = webserver.jinja_env.get_template('pages/index.html')
    html = template.render()
    return {'type': 'text/html', 'content': html}

@webserver.get('/studio/<studio_id>')
def serve_studio(studio_id, payload=None):
    """Serve a studio page by ID."""
    template = webserver.jinja_env.get_template('pages/studio.html')
    html = template.render(id=studio_id)
    return {'type': 'text/html', 'content': html}


## Main ##

def main():
    try:
        # Start Webserver
        webserver.start()

        # Start Runtime
        runtime.start()

        try:
            # Keep alive
            while True:
                sleep(10)
        except KeyboardInterrupt:
            logger.info("Exiting...")
        finally:
            # Cleanup and exit
            webserver.stop()
            runtime.stop()

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()