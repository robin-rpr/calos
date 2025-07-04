#!/usr/bin/env python3

import logging
import os
import signal
import subprocess
import sys
import threading
import time
import sass

from routes.container import container_blueprint, container_api_blueprint
from flask import Flask, render_template, request, abort
from concurrent.futures import ThreadPoolExecutor
from flask_caching import Cache
from datetime import timedelta

# Add the share directory to Python path for imports
# SHAREDIR is defined by Cython compilation
try:
    SHAREDIR
except NameError:
    SHAREDIR = None

# Application
if SHAREDIR is not None:
    app = Flask(__name__, template_folder=SHAREDIR, static_folder=SHAREDIR)
else:
    app = Flask(__name__)

# Caching
app.cache = Cache(app, config={'CACHE_TYPE': 'simple'})

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

# Session Cookies
app.config['SESSION_COOKIE_SECURE'] = app.config['ENVIRONMENT'] == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=90)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Threadpool Executor
executor = ThreadPoolExecutor()

def before_request():
    """Cache Stylesheets"""
    scss_file = 'static/styles/main.scss'
    css_file = 'static/styles/main.css'
    with open(css_file, 'w', -1, 'utf8') as f:
        f.write(sass.compile(filename=scss_file))

def add_header(response):
    """Cache Static Files"""
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 86400
        response.cache_control.no_cache = None
        response.cache_control.public = True
    return response

def signal_handler(self, signum, frame):
    """Handle Signals"""
    logger.info(f"SIGNAL: {signum}, Shutting down...")
    # Shutdown executor
    if app.clearly:
        with app.clearly.lock:
            for container_id in list(app.clearly.containers.keys()):
                app.clearly.stop_container(container_id)
    # Shutdown thread pool
    executor.shutdown(wait=True)
    sys.exit(0)

class Clearly:
    """Clearly Executor"""
    
    def __init__(self):
        # container_id -> container_info
        self.containers = {} 
        self.lock = threading.Lock()
        self.temp_dir = "/tmp/clearly"
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def start_container(self, container_id, image, command=None, environment=None):
        """Start a container"""
        try:
            with self.lock:
                if container_id in self.containers:
                    return {"error": "Container already exists"}
                
                # Prepare command
                cmd = ["clearly", "run", image]
                
                if environment:
                    for key, value in environment.items():
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
                )
                
                # Store container info
                container_info = {
                    "id": container_id,
                    "image": image,
                    "command": command,
                    "environment": environment,
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
        """Stop a container"""
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

def main():
    """Main entry point"""
    try:
        # Register Processor
        @app.context_processor
        def context():
            scripts = []
            def script(script):
                scripts.append(script)
                return ''
            return dict(script=script, scripts=lambda: scripts)
        
        # Register Routes
        @app.route('/')
        @app.cache.cached(timeout=86400) # 24 hours
        def index():
            """Index"""
            try:
                example = "Example5"

            except Exception as e:
                app.logger.error("Failed to load index: %s", str(e), exc_info=True)
                return abort(500, description="An error occurred")

            return render_template('pages/index.html', example=example)

        # Register Blueprints
        app.register_blueprint(container_blueprint, url_prefix='/container')
        app.register_blueprint(container_api_blueprint, url_prefix='/api/container')

        # Register Signal Handlers
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        # Register Clearly
        app.clearly = Clearly()

        # Start Server
        app.run(
            host='0.0.0.0',
            port=8080,
            debug=True,
            extra_files=['templates/**/*.html', 'static/**/*.scss']
        )
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()