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
import _proxy as _proxy
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
    host=(lambda: next(
        (sys.argv[i+1] for i, v in enumerate(sys.argv)
         if v == '--host' and i+1 < len(sys.argv)),
        '127.0.0.1'
    ))(),
    port=(lambda: int(next(
        (sys.argv[i+1] for i, v in enumerate(sys.argv)
         if v == '--port' and i+1 < len(sys.argv)),
        8080
    )))(),
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
def deploy(payload=None, name=None):
    """Deploy a new container."""
    try:
        runtime.deploy({
            "t": "DEPLOY",
            "deploy": {
                "id": name,
                "services": payload["services"]
            },
            "ts": time.time()
        })

        return { "success": True, "id": name }
    except Exception as e:
        logger.error(f"Failed to deploy: {e}", exc_info=True)
        return { "error": str(e) }

@webserver.get('/api/containers')
def list_containers(payload=None, type=None):
    """List all containers."""
    try:
        now = time.time();
        containers = {}
        with runtime.lock:
            for k, v in runtime.local.items():
                if type and v.get("type") != type: continue
                if v.get("status") != "removed": 
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
                    if type and v.get("type") != type: continue
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
        logger.error(f"Failed to list containers: {e}", exc_info=True)
        return { "error": str(e) }

@webserver.get('/api/containers/<container_id>')
def get_container(container_id, payload=None):
    """Get container details by ID."""
    return None

@webserver.get('/api/containers/<container_id>/logs')
def get_container_logs(container_id, payload=None):
    """Get container logs by ID."""
    try:
        cmd = ["clearly", "logs", container_id]

        # Execute command and capture output.
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        
        return {"success": True, "stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        logger.error(f"Failed to get logs for container {container_id}: {e}")
        return {"error": str(e)}

@webserver.get('/api/containers/<container_id>/proxy/<port>')
def get_container_proxy(container_id, port, payload=None):
    """Get container proxy by ID."""
    try:
        ip_address = runtime.local[container_id].get("ip_address")
        if not ip_address:
            raise Exception("Couldn't connect to container")
        
        proxy = _proxy.Proxy(ip_address, int(port), "0.0.0.0", int(0))
        timeout = proxy.start(timeout=300)

        return {"success": True, "proxy": proxy.socket.getsockname()[1], "timeout": timeout}
    except Exception as e:
        logger.error(f"Failed to get proxy for container {container_id}: {e}")
        return {"error": str(e)}

@webserver.post('/api/containers')
def start_container(payload=None):
    """Start a new container."""
    try:
        cmd = [
            "clearly", "run", payload.get("image", "ubuntu:latest"),
            "--name", payload.get("name", str(uuid.uuid4())[:8]), "--detach"
        ]

        # (Optional) Static IP.
        if payload.get("ip"):
            cmd.extend(["--ip", payload.get("ip")])

        # (Optional) Per-peer allow list.
        if payload.get("allow"):
            for peer_ip in payload.get("allow"):
                cmd.extend(["--allow", str(peer_ip)])

        # (Optional) Sysctl parameters list.
        if payload.get("sysctl"):
            for key, value in payload.get("sysctl").items():
                cmd.extend(["--sysctl", f"{key}={value}"])

        # (Optional) Capability add list.
        if payload.get("cap_add"):
            for cap in payload.get("cap_add"):
                cmd.extend(["--cap-add", str(cap)])

        # (Optional) Capability drop list.
        if payload.get("cap_drop"):
            for cap in payload.get("cap_drop"):
                cmd.extend(["--cap-drop", str(cap)])

        # (Optional) Publish list.
        if payload.get("publish"):
            if isinstance(payload.get("publish"), dict):
                for key, value in payload.get("publish").items():
                    cmd.extend(["--publish", f"{key}:{value}"])
            elif isinstance(payload.get("publish"), list):
                for entry in payload.get("publish"):
                    cmd.extend(["--publish", str(entry)])
        
        # (Optional) Environment list.
        if payload.get("environment"):
            if isinstance(payload.get("environment"), dict):
                for key, value in payload.get("environment").items():
                    cmd.extend(["--env", f"{key}={value}"])
            elif isinstance(payload.get("environment"), list):
                for entry in payload.get("environment"):
                    cmd.extend(["--env", str(entry)])
        
        # (Optional) Command list.
        if payload.get("command"):
            cmd.extend(["--"] + payload.get("command"))

        # Execute command.
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            start_new_session=True
        )

        process.wait()
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)

        return {"success": True}
    except Exception as e:
        logger.error(f"Failed to start container {payload.get('name')}: {e}")
        return {"error": str(e)}

@webserver.delete('/api/containers/<container_id>')
def stop_container(container_id, payload=None):
    """Stop a container by ID."""
    try:
        cmd = ["clearly", "stop", container_id]

        # Execute command.
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, check=True)
        
        return {"success": True}    
    except Exception as e:
        logger.error(f"Failed to stop container {container_id}: {e}")
        return {"error": str(e)}

@webserver.get('/api/machines')
def list_machines(payload=None):
    """List all discovered machines."""
    return runtime.cluster


## Pages ##

@webserver.get('/')
def serve_index(payload=None):
    """Serve the main index page."""
    template = webserver.jinja_env.get_template('pages/index.html')
    html = template.render()
    return {'type': 'text/html', 'content': html}

@webserver.get('/studio/<container_id>')
def serve_studio(container_id, payload=None):
    """Serve a studio page by container ID."""
    template = webserver.jinja_env.get_template('pages/studio.html')
    html = template.render(id=container_id)
    return {'type': 'text/html', 'content': html}


## Main ##

def main():
    try:
        # Startup.
        webserver.start()
        runtime.start()

        try:
            # Keep alive.
            while True:
                sleep(10)
        except KeyboardInterrupt:
            logger.info("Shutting down...")

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()