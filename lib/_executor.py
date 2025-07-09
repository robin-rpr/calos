import subprocess
import threading
import logging
import time
import os
import re

import _proxy as _proxy

## Classes ##

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
            with self.lock:
                if id is None:
                    return {"error": "Container ID is required"}
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
                    "ip": (lambda pid=process.pid: (
                        open(f"/run/clearly/net/{pid}").read().strip()
                        if os.path.exists(f"/run/clearly/net/{pid}") else None
                    )),
                    "process": process,
                    "start_time": time.time(),
                    "status": "running",
                    "stdout_log": [],
                    "stderr_log": [],
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
                        "ip": info["ip"](),
                        "start_time": info["start_time"],
                        "image": info["image"],
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
            
            def read_stdout():
                """Read stdout in a separate thread"""
                try:
                    for line in iter(process.stdout.readline, ''):
                        if line:
                            line = line.strip()
                            with self.lock:
                                container_info["stdout_log"].append({
                                    "timestamp": time.time(),
                                    "line": line
                                })
                except Exception as e:
                    self.logger.error(f"Error reading stdout for container {id}: {e}")
            
            def read_stderr():
                """Read stderr in a separate thread"""
                try:
                    for line in iter(process.stderr.readline, ''):
                        if line:
                            line = line.strip()
                            with self.lock:
                                container_info["stderr_log"].append({
                                    "timestamp": time.time(),
                                    "line": line
                                })
                except Exception as e:
                    self.logger.error(f"Error reading stderr for container {id}: {e}")

            # Start separate threads for reading stdout and stderr
            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            
            stdout_thread.start()
            stderr_thread.start()
            
            # Wait for both threads to complete (when process ends)
            stdout_thread.join()
            stderr_thread.join()
                    
        except Exception as e:
            self.logger.error(f"Error collecting logs for container {id}: {e}")

class StudioExecutor(Executor):
    """StudioExecutor"""

    def __init__(self):
        super().__init__()
        # id -> studio_info
        self.studios = {}

    def start_studio(self, id, containers=[]):
        """Start a studio, which is a group of containers"""
        if id is None:
            return {"error": "Studio ID is required"}
        if id in self.studios:
            return {"error": "Studio already exists"}
        
        ids = []

        for container in containers:
            result = self.start_container(
                f"{id}-{container['id']}",
                image=container.get('image', None),
                command=container.get('command', []),
                environment=container.get('environment', {})
            )
            if "error" in result:
                return result

            while True:
                ip_address = self.containers[result["id"]]["ip"]()
                if ip_address:
                    break
                # Wait for container.
                time.sleep(0.1)

            result_proxy = {}
            for host, guest in container.get('proxy', {}).items():
                proxy = _proxy.Proxy(ip_address, int(guest), "0.0.0.0", int(host))
                result_proxy[guest] = proxy
                proxy.start()
                
            ids.append({
                "id": result["id"],
                "proxy": result_proxy
            })

        studio_info = {
            "id": id,
            "status": "running",
            "containers": ids
        }

        self.studios[id] = studio_info
        return {"success": True, "id": id}

    def stop_studio(self, id):
        """Stop a studio and all its containers"""
        try:
            with self.lock:
                if id not in self.studios:
                    return {"error": "Studio not found"}
                
                studio_info = self.studios[id]
                containers = studio_info["containers"].copy() # Avoid holding lock.

                # Mark studio as stopping
                studio_info["status"] = "stopping"

            # Stop all containers in the studio
            for container in containers:
                self.stop_container(container["id"])
                for _, proxy in container["proxy"].items():
                    proxy.stop()
            
            # Mark studio as stopped
            with self.lock:
                if id in self.studios:
                    self.studios[id]["status"] = "stopped"
                
            self.logger.info(f"Stopped studio {id}")
            return {"success": True, "id": id}
                
        except Exception as e:
            self.logger.error(f"Failed to stop studio {id}: {e}")
            return {"error": str(e)}

    def get_studio(self, id):
        """Get a studio"""
        try:
            with self.lock:
                if id not in self.studios:
                    return {"error": "Studio not found"}
                return {"success": True, "id": id, **self.studios[id]}
        except Exception as e:
            self.logger.error(f"Failed to get studio {id}: {e}")
            return {"error": str(e)}
    
    def get_studio_logs(self, id):
        """Get logs from a studio"""
        try:
            with self.lock:
                if id not in self.studios:
                    return {"error": "Studio not found"}

                studio_info = self.studios[id]
                container_ids = studio_info["containers"].copy()

            # Release lock before calling get_container_logs to avoid deadlock
            logs = {}
            for container_info in container_ids:
                container_logs = self.get_container_logs(container_info["id"])
                if "error" not in container_logs:
                    logs[container_info["id"]] = {
                        "stdout": container_logs["stdout"],
                        "stderr": container_logs["stderr"],
                        "status": container_logs["status"]
                    }

            return {
                "success": True,
                "id": id,
                "logs": logs
            }
                
        except Exception as e:
            self.logger.error(f"Failed to get logs for studio {id}: {e}")
            return {"error": str(e)}

    def list_studios(self):
        """List all studios"""
        try:
            with self.lock:
                studio_list = []
                for id, info in self.studios.items():
                    studio_list.append({
                        "id": id,
                        "status": info["status"],
                        "containers": info["containers"]
                    })
                return {"success": True, "studios": studio_list}
                
        except Exception as e:
            self.logger.error(f"Failed to list studios: {e}")
            return {"error": str(e)}
