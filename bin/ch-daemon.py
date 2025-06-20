#!/usr/bin/env python3
"""
Clearstack Daemon
A lightweight daemon for managing Clearstack containers.
"""

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import tempfile
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/clearstack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ContainerManager:
    """Manages Clearstack containers"""
    
    def __init__(self):
        self.containers = {}  # container_id -> container_info
        self.lock = threading.Lock()
        self.temp_dir = "/tmp/clearstack"
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def start_container(self, container_id, image_path, command=None, env_vars=None):
        """Start a Clearstack container"""
        try:
            with self.lock:
                if container_id in self.containers:
                    return {"error": "Container already exists"}
                
                # Create container directory
                container_dir = os.path.join(self.temp_dir, container_id)
                os.makedirs(container_dir, exist_ok=True)
                
                # Prepare command
                cmd = ["charlie", "run", image_path]
                
                if env_vars:
                    for key, value in env_vars.items():
                        cmd.extend(["--env", f"{key}={value}"])
                
                if command:
                    cmd.extend(["--"] + command)
                else:
                    cmd.extend(["--", "/bin/bash", "-c", "sleep infinity"])
                
                # Start container process
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=container_dir
                )
                
                # Store container info
                container_info = {
                    "id": container_id,
                    "image_path": image_path,
                    "command": command,
                    "env_vars": env_vars,
                    "pid": process.pid,
                    "process": process,
                    "start_time": time.time(),
                    "status": "running",
                    "stdout_log": [],
                    "stderr_log": []
                }
                
                self.containers[container_id] = container_info
                
                # Start log collection thread
                log_thread = threading.Thread(
                    target=self._collect_logs,
                    args=(container_id,),
                    daemon=True
                )
                log_thread.start()
                
                logger.info(f"Started container {container_id} with PID {process.pid}")
                return {"success": True, "container_id": container_id, "pid": process.pid}
                
        except Exception as e:
            logger.error(f"Failed to start container {container_id}: {e}")
            return {"error": str(e)}
    
    def stop_container(self, container_id):
        """Stop a Clearstack container"""
        try:
            with self.lock:
                if container_id not in self.containers:
                    return {"error": "Container not found"}
                
                container_info = self.containers[container_id]
                process = container_info["process"]
                
                # Try graceful shutdown first
                process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    process.kill()
                    process.wait()
                
                container_info["status"] = "stopped"
                container_info["end_time"] = time.time()
                
                logger.info(f"Stopped container {container_id}")
                return {"success": True, "container_id": container_id}
                
        except Exception as e:
            logger.error(f"Failed to stop container {container_id}: {e}")
            return {"error": str(e)}
    
    def get_container_logs(self, container_id):
        """Get logs from a container"""
        try:
            with self.lock:
                if container_id not in self.containers:
                    return {"error": "Container not found"}
                
                container_info = self.containers[container_id]
                return {
                    "success": True,
                    "container_id": container_id,
                    "stdout": container_info["stdout_log"],
                    "stderr": container_info["stderr_log"],
                    "status": container_info["status"]
                }
                
        except Exception as e:
            logger.error(f"Failed to get logs for container {container_id}: {e}")
            return {"error": str(e)}
    
    def list_containers(self):
        """List all containers"""
        try:
            with self.lock:
                container_list = []
                for container_id, info in self.containers.items():
                    container_list.append({
                        "id": container_id,
                        "status": info["status"],
                        "pid": info["pid"],
                        "start_time": info["start_time"],
                        "image_path": info["image_path"]
                    })
                return {"success": True, "containers": container_list}
                
        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            return {"error": str(e)}
    
    def _collect_logs(self, container_id):
        """Collect logs from container process"""
        try:
            container_info = self.containers[container_id]
            process = container_info["process"]
            
            # Read stdout
            for line in iter(process.stdout.readline, ''):
                if line:
                    container_info["stdout_log"].append({
                        "timestamp": time.time(),
                        "line": line.strip()
                    })
            
            # Read stderr
            for line in iter(process.stderr.readline, ''):
                if line:
                    container_info["stderr_log"].append({
                        "timestamp": time.time(),
                        "line": line.strip()
                    })
                    
        except Exception as e:
            logger.error(f"Error collecting logs for container {container_id}: {e}")

class ClearstackRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Clearstack daemon"""
    
    def __init__(self, *args, container_manager=None, **kwargs):
        self.container_manager = container_manager
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            if path == "/containers":
                # List all containers
                response = self.container_manager.list_containers()
                self._send_json_response(response)
                
            elif path.startswith("/containers/") and "/logs" in path:
                # Get container logs
                container_id = path.split("/")[2]
                response = self.container_manager.get_container_logs(container_id)
                self._send_json_response(response)
                
            elif path == "/health":
                # Health check
                self._send_json_response({"status": "healthy"})
                
            else:
                self._send_error_response(404, "Not found")
                
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self._send_error_response(500, str(e))
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path == "/containers":
                # Start a new container
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                request_data = json.loads(post_data.decode('utf-8'))
                
                container_id = request_data.get('container_id')
                image_path = request_data.get('image_path')
                command = request_data.get('command')
                env_vars = request_data.get('env_vars', {})
                
                if not container_id or not image_path:
                    self._send_error_response(400, "Missing required fields: container_id, image_path")
                    return
                
                response = self.container_manager.start_container(container_id, image_path, command, env_vars)
                self._send_json_response(response)
                
            else:
                self._send_error_response(404, "Not found")
                
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self._send_error_response(500, str(e))
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path.startswith("/containers/"):
                # Stop a container
                container_id = path.split("/")[2]
                response = self.container_manager.stop_container(container_id)
                self._send_json_response(response)
                
            else:
                self._send_error_response(404, "Not found")
                
        except Exception as e:
            logger.error(f"Error handling DELETE request: {e}")
            self._send_error_response(500, str(e))
    
    def _send_json_response(self, data):
        """Send JSON response"""
        response = json.dumps(data, indent=2)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))
    
    def _send_error_response(self, status_code, message):
        """Send error response"""
        error_data = {"error": message}
        response = json.dumps(error_data, indent=2)
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"{self.address_string()} - {format % args}")

class ClearstackDaemon:
    """Main daemon class"""
    
    def __init__(self, host='0.0.0.0', port=8080, max_workers=10):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.container_manager = ContainerManager()
        self.server = None
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.running = False
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def start(self):
        """Start the daemon"""
        try:
            # Create custom request handler with container manager
            def handler(*args, **kwargs):
                return ClearstackRequestHandler(*args, container_manager=self.container_manager, **kwargs)
            
            self.server = HTTPServer((self.host, self.port), handler)
            self.running = True
            
            logger.info(f"Clearstack daemon starting on {self.host}:{self.port}")
            logger.info(f"Thread pool size: {self.max_workers}")
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            server_thread.start()
            
            logger.info("Clearstack daemon started successfully")
            
            # Keep main thread alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start daemon: {e}")
            raise
    
    def stop(self):
        """Stop the daemon"""
        logger.info("Stopping Clearstack daemon...")
        self.running = False
        
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        # Stop all containers
        with self.container_manager.lock:
            for container_id in list(self.container_manager.containers.keys()):
                self.container_manager.stop_container(container_id)
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logger.info("Clearstack daemon stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)

def main():
    """Main entry point"""
    try:
        # Parse command line arguments
        import argparse
        parser = argparse.ArgumentParser(description='Clearstack Daemon')
        parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
        parser.add_argument('--port', type=int, default=4242, help='Port to bind to')
        parser.add_argument('--max-workers', type=int, default=10, help='Maximum thread pool workers')
        parser.add_argument('--daemon', action='store_true', help='Run as daemon')
        
        args = parser.parse_args()
        
        # Create and start daemon
        daemon = ClearstackDaemon(
            host=args.host,
            port=args.port,
            max_workers=args.max_workers
        )
        
        if args.daemon:
            # Fork to background
            pid = os.fork()
            if pid > 0:
                # Parent process
                sys.exit(0)
            else:
                # Child process
                os.setsid()
                os.umask(0)
        
        daemon.start()
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()