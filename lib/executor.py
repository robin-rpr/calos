import subprocess
import threading
import time
import os
import logging

class Executor:
    """Executor"""
    
    def __init__(self):
        # container_id -> container_info
        self.containers = {} 
        self.lock = threading.Lock()
        self.temp_dir = "/tmp/clearly"
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def init_app(self, app):
        """Initialize the executor"""
        self.app = app
    
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
                
                self.app.logger.info(f"Started container {container_id} with PID {process.pid}")
                return {"success": True, "container_id": container_id, "pid": process.pid}
                
        except Exception as e:
            self.app.logger.error(f"Failed to start container {container_id}: {e}")
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
                
                self.app.logger.info(f"Stopped container {container_id}")
                return {"success": True, "container_id": container_id}
                
        except Exception as e:
            self.app.logger.error(f"Failed to stop container {container_id}: {e}")
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
            self.app.logger.error(f"Failed to get logs for container {container_id}: {e}")
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
            self.app.logger.error(f"Failed to list containers: {e}")
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
            self.app.logger.error(f"Error collecting logs for container {container_id}: {e}")
