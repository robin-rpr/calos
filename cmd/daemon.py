#!/usr/bin/env python3

import sys
import os
import logging
import subprocess
import uuid
import socket
import threading
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

import _syncthing as _syncthing
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
listener = ServiceListener()

# Syncthing
syncthing = _syncthing.Syncthing(
    config_dir=Path.home() / ".config/clearly",
    folder_dir="/srv/clearly",
    ip_address=get_interface_address('clearly0')
)

# Webserver
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

@server.get('/api/machines')
def list_machines(payload=None):
    """List all discovered Clearly machines."""
    return listener.get_services()


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


## Helpers ##

def get_interface_address(ifname='eth0'):
    """Get the IP address of an interface"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915, # SIOCGIFADDR
        struct.pack('256s', ifname.encode('utf-8')[:15])
    )[20:24])


## Classes ##

class ServiceListener(object):
    """A ServiceListener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation to cache information
    as it arrives as well as dynamically add and remove services from Syncthing.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is availble for reading."""

    def __init__(self):
        self.services = {} # Discovered services
        self.lock = threading.Lock()
    
    def addService(self, zeroconf, service_type, name):
        """Called when a new service is discovered."""
        try:
            # Get service info
            info = zeroconf.getServiceInfo(service_type, name, timeout=3000)
            if info:
                with self.lock:
                    self.services[name] = {
                        'name': name,
                        'address': socket.inet_ntoa(info.getAddress()) if info.getAddress() else None,
                        'port': info.getPort(),
                        'properties': info.getProperties(),
                        'server': info.getServer()
                    }

                # Add the service to Syncthing
                syncthing.add_peer(info.getProperties()['device_id'], info.getAddress())

                # Restart Syncthing to pick up the new peer
                syncthing.stop()
                syncthing.start()

                # Log the discovery
                logger.info(f"Discovered service: {name} at {socket.inet_ntoa(info.getAddress())}:{info.getPort()}")
        except Exception as e:
            logger.error(f"Error getting service info for {name}: {e}")
    
    def removeService(self, zeroconf, service_type, name):
        """Called when a service is removed."""
        with self.lock:
            if name in self.services:
                removed_service = self.services.pop(name)

                # Remove the service from Syncthing
                syncthing.remove_peer(removed_service.get('properties')['device_id'])

                # Restart Syncthing to pick up the peer removal
                syncthing.stop()
                syncthing.start()

                # Log the removal
                logger.info(f"Service removed: {name} at {removed_service.get('address')}:{removed_service.get('port')}")
    
    def get_services(self):
        """Get a copy of the current services map."""
        with self.lock:
            return self.services.copy()


## Main ##

def main():
    try:
        # Create a mDNS service
        service_address = get_interface_address('clearly0')
        service_name = f"clearly-{service_address}._clearly._tcp.local."
        service_info = _zeroconf.ServiceInfo(
            "_clearly._tcp.local.",
            service_name,
            service_address,
            12345,
            0, 0,
            {
                'version': '1.0',
                'device_id': syncthing.device_id,
                'service': 'clearly'
            }
        )

        # Register the service
        zeroconf.registerService(service_info)
        
        # Register a listener for other services
        zeroconf.addServiceListener("_clearly._tcp.local.", listener)

        # Start the web server
        server.start()
        
        # Keep the main thread alive
        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            # Unregister the service
            zeroconf.unregisterService(service_info)
            zeroconf.close()

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()