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
from time import sleep
from pathlib import Path
import xml.etree.ElementTree as ET

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
import _storage as _storage
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
zeroconf = None
listener = None

# Webserver
webserver = WebServer(
    host='127.0.0.1',
    port=8080,
    static_dir=STATIC_DIR,
    template_dir=TEMPLATE_DIR,
)

# Storage
storage = _storage.Storage(
    name='runtime',
    image_dir='/var/lib/clearly',
    mount_dir='/run/clearly',
    size='10G'
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

## Routes ##

@webserver.get('/api/containers')
def list_containers(payload=None):
    """List all containers."""
    return executor.list_containers()

@webserver.get('/api/containers/<container_id>')
def get_container(container_id, payload=None):
    """Get container details by ID."""
    return executor.get_container(container_id)

@webserver.get('/api/containers/<container_id>/logs')
def get_container_logs(container_id, payload=None):
    """Get container logs by ID."""
    return executor.get_container_logs(container_id)

@webserver.post('/api/containers')
def start_container(payload):
    """Start a new container."""
    return executor.start_container(
        payload.get('name', str(uuid.uuid4())[:8]),
        payload.get('image', 'ubuntu:latest'),
        payload.get('command', []),
        payload.get('publish', {}),
        payload.get('environment', {})
    )

@webserver.delete('/api/containers/<container_id>')
def stop_container(container_id, payload=None):
    """Stop a container by ID."""
    try:
        subprocess.run(['clearly', 'stop', container_id], capture_output=True, text=True, check=True)
        return {'status': 'stopped', 'id': container_id}
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to stop container {container_id}: {e.stderr}")
        raise Exception(f"Error stopping container: {e.stderr}")

@webserver.get('/api/studios')
def list_studios(payload=None):
    """List all studios."""
    return studio_executor.list_studios()

@webserver.get('/api/studios/<studio_id>')
def get_studio(studio_id, payload=None):
    """Get studio details by ID."""
    return studio_executor.get_studio(studio_id)

@webserver.get('/api/studios/<studio_id>/logs')
def get_studio_logs(studio_id, payload=None):
    """Get studio logs by ID."""
    return studio_executor.get_studio_logs(studio_id)

@webserver.post('/api/studios')
def start_studio(payload):
    """Start a new studio."""
    name = payload.get('name', str(uuid.uuid4())[:8])
    return studio_executor.start_studio(name)

@webserver.delete('/api/studios/<studio_id>')
def stop_studio(studio_id, payload=None):
    """Stop a studio by ID."""
    return studio_executor.stop_studio(studio_id)

@webserver.get('/api/machines')
def list_machines(payload=None):
    """List all discovered Clearly machines."""
    return listener.services.copy()


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


## Helpers ##

def get_interface_address(ifname='eth0'):
    """Get the IP address of an interface (as 4-byte packed format)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915, # SIOCGIFADDR
        struct.pack('256s', ifname.encode('utf-8')[:15])
    )[20:24]


## Classes ##

class ServiceListener(object):
    """A ServiceListener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation to cache information
    as it arrives as well as dynamically add and remove services from the cluster.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is availble for reading."""

    def __init__(self):
        self.lock = threading.Lock()
        self.pending = set()
        self.services = {}

    def addService(self, zeroconf, type, name):
        """Called when a new service is discovered."""
        with self.lock:
            if name in self.services or name in self.pending:
                # Skip if already known or being resolved.
                return
            # Add to the pending set.
            self.pending.add(name)

        # Resolve in background.
        threading.Thread(
            target=self._resolve_loop, args=(zeroconf, type, name),
            daemon=True
        ).start()

    def _resolve_loop(self, zeroconf, type, name):
        """Resolve SRV/TXT/A; retry until it succeeds."""
        while True:
            try:
                # Lookup the service info.
                # This is blocking, which is why we run it in a thread.
                info = zeroconf.getServiceInfo(type, name, timeout=2000)
            except Exception as e:
                logger.error(f"Lookup failed for {name}: {e}")
                info = None

            if info:
                service = {
                    'name': name,
                    'address': socket.inet_ntoa(info.getAddress()),
                    'port': info.getPort(),
                    'weight': info.getWeight(),
                    'priority': info.getPriority(),
                    'properties': info.getProperties(),
                    'server': info.getServer(),
                }
                # Add to the cache.
                logger.info("Waiting for lock... for %s", name)
                with self.lock:
                    logger.info("Lock acquired. for %s", name)
                    self.services[name] = service
                    self.pending.discard(name)

                logger.info("Services are now: %s", self.services)

                # Log the discovery.
                logger.info(f"Discovered: {name} at {service['address']}")
                return

            # Not resolved yet; try again later.
            time.sleep(2)

    def removeService(self, zeroconf, type, name):
        """Called when a service is removed."""
        logger.info("A removal has been called for %s", name)
        with self.lock:
            logger.info("Lock acquired. for removal of %s", name)
            self.pending.discard(name)
            if name in self.services:
                service = self.services.pop(name)
                logger.info(f"Removed: {name} at {service.get('address')}")


## Main ##

def main():
    try:
        # Zeroconf
        global listener
        global zeroconf

        listener = ServiceListener()
        service_address = get_interface_address('clearly0')
        zeroconf = _zeroconf.Zeroconf(bindaddress=socket.inet_ntoa(service_address))
        browser = _zeroconf.ServiceBrowser(zeroconf, "_clearly._tcp.local.", listener)
        version = subprocess.check_output(['clearly', 'version']).decode('utf-8').strip()
        identifier = open('/etc/machine-id').read().strip()

        # Create a Zeroconf service
        service_name = f"clearly-{identifier}._clearly._tcp.local."
        service_info = _zeroconf.ServiceInfo(
            type="_clearly._tcp.local.",
            name=service_name,
            address=service_address,
            port=0,
            weight=0,
            priority=0,
            properties={
                'version': version,
                'identifier': identifier,
                'service': 'clearly'
            },
        )

        # Register our own Zeroconf service
        zeroconf.registerService(service_info)

        # Start Webserver
        webserver.start()

        # Peer discovery timeout
        sleep(60)

        # Start Storage
        #storage.set_nodes(listener.get_services())
        #storage.start()
        
        try:
            # Keep alive
            while True:
                sleep(1)
        except KeyboardInterrupt:
            logger.info("Exiting...")
        finally:
            # Cleanup and exit
            zeroconf.unregisterService(service_info)
            zeroconf.close()
            storage.stop()

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()