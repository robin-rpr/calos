import subprocess
import threading
import logging
import time
import os

class Executor:
    """Executor"""
    
    def __init__(self):
        # id -> container_info
        self.containers = {} 
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.temp_dir = "/tmp/clearly"
        os.makedirs(self.temp_dir, exist_ok=True)
    
    def start_container(self, id, image, command=[], publish={}, environment={}):
        """Start a container"""
        try:
            print(f"Starting container {id} with image {image} and command {command} and environment {environment}")
            with self.lock:
                if id in self.containers:
                    return {"error": "Container already exists"}
                
                # Prepare command
                cmd = ["clearly", "run", image]

                if publish:
                    for key, value in publish.items():
                        cmd.extend(["--publish", f"{key}:{value}"])
                
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
                    "id": id,
                    "image": image,
                    "command": command,
                    "publish": publish,
                    "environment": environment,
                    "pid": process.pid,
                    "process": process,
                    "start_time": time.time(),
                    "status": "running",
                    "stdout_log": [],
                    "stderr_log": []
                }
                
                self.containers[id] = container_info
                
                # Start log collection thread
                log_thread = threading.Thread(
                    target=self._collect_logs,
                    args=(id,),
                    daemon=True
                )
                log_thread.start()
                
                self.logger.info(f"Started container {id} with PID {process.pid}")
                return {"success": True, "id": id, "pid": process.pid}
                
        except Exception as e:
            self.logger.error(f"Failed to start container {id}: {e}")
            return {"error": str(e)}
    
    def stop_container(self, id):
        """Stop a container"""
        try:
            with self.lock:
                if id not in self.containers:
                    return {"error": "Container not found"}
                
                container_info = self.containers[id]
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
                
                self.logger.info(f"Stopped container {id}")
                return {"success": True, "id": id}
                
        except Exception as e:
            self.logger.error(f"Failed to stop container {id}: {e}")
            return {"error": str(e)}
    
    def get_container_logs(self, id):
        """Get logs from a container"""
        try:
            with self.lock:
                if id not in self.containers:
                    return {"error": "Container not found"}
                
                container_info = self.containers[id]
                return {
                    "success": True,
                    "id": id,
                    "stdout": container_info["stdout_log"],
                    "stderr": container_info["stderr_log"],
                    "status": container_info["status"]
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get logs for container {id}: {e}")
            return {"error": str(e)}
    
    def list_containers(self):
        """List all containers"""
        try:
            with self.lock:
                container_list = []
                for id, info in self.containers.items():
                    container_list.append({
                        "id": id,
                        "status": info["status"],
                        "publish": info["publish"],
                        "pid": info["pid"],
                        "start_time": info["start_time"],
                        "image": info["image"]
                    })
                return {"success": True, "containers": container_list}
                
        except Exception as e:
            self.logger.error(f"Failed to list containers: {e}")
            return {"error": str(e)}
    
    def _collect_logs(self, id):
        """Collect logs from container process"""
        try:
            container_info = self.containers[id]
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
            self.logger.error(f"Error collecting logs for container {id}: {e}")
