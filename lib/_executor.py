import subprocess
import logging
import json

import _proxy as _proxy


## Constants ##

logger = logging.getLogger(__name__)


## Classes ##

class Executor():
    """Executor"""

    def start_container(self, name: str, image: str, command: list,
                        publish, environment: dict, ip: str = None, allow: list = None) -> dict:
        """Start a container"""
        try:
            cmd = ["clearly", "run", image, "--name", name, "--detach"]

            # Optional static IP
            if ip:
                cmd.extend(["--ip", ip])

            # Optional per-peer allow list
            if allow:
                for peer_ip in allow:
                    cmd.extend(["--allow", str(peer_ip)])

            # Publish can be a dict (host->container) or a list of strings
            if publish:
                if isinstance(publish, dict):
                    for key, value in publish.items():
                        cmd.extend(["--publish", f"{key}:{value}"])
                elif isinstance(publish, list):
                    for entry in publish:
                        # Accept already formatted strings like "8080:80" or "NET:src:dst"
                        cmd.extend(["--publish", str(entry)])
            
            if environment:
                for key, value in environment.items():
                    cmd.extend(["--env", f"{key}={value}"])
            
            if command:
                cmd.extend(["--"] + command)

            # Execute command.
            logger.info(f"Starting container {name} with command: {cmd}")
            subprocess.Popen(cmd)
            
            return {"success": True}
                
        except Exception as e:
            logger.error(f"Failed to start container {name}: {e}")
            return {"error": str(e)}
    
    def stop_container(self, name):
        """Stop a container"""
        try:
            cmd = ["clearly", "stop", name]

            # Execute command.
            subprocess.Popen(cmd)
            
            return {"success": True}
                
        except Exception as e:
            logger.error(f"Failed to stop container {name}: {e}")
            return {"error": str(e)}
    
    def get_container_logs(self, name):
        """Get logs from a container"""
        try:
            cmd = ["clearly", "logs", name]

            # Execute command and capture output.
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            return {"success": True, "stdout": result.stdout, "stderr": result.stderr}
                
        except Exception as e:
            logger.error(f"Failed to get logs for container {name}: {e}")
            return {"error": str(e)}
    
    def list_containers(self):
        """List all containers"""
        try:
            cmd = ["clearly", "list", "--json"]

            # Execute command and capture output.
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            return {"success": True, "containers": json.loads(result.stdout)}
                
        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            return {"error": str(e)}

    
class StudioExecutor(Executor):
    """StudioExecutor"""

    def __init__(self):
        super().__init__()

    def start_studio(self, name):
        """Start a studio, which is a group of containers"""

        containers = [
            {
                "name": "vscode",
                "image": "codercom/code-server:4.101.2-39",
                "command": ["/usr/bin/entrypoint.sh", "--bind-addr", "0.0.0.0:8080", ".", "--auth", "none"],
                "proxy": { "0": "8080" }
            },
            {
                "name": "jupyter",
                "image": "jupyter/minimal-notebook:python-3.9.13",
                "command": [
                    "tini", "-g", "--", "start-notebook.sh",
                    "--ServerApp.token=",
                    "--ServerApp.password=",
                    "--ServerApp.allow_origin=*",
                    "--ServerApp.disable_check_xsrf=True",
                    "--ServerApp.tornado_settings={\"headers\":{\"Content-Security-Policy\":\"frame-ancestors *\"}}"
                ],
                "proxy": { "0": "8888" }
            }
        ]
        
        # Start all containers.
        for container in containers:
            result = self.start_container(
                name=f"~{name}-{container['name']}",
                image=container.get('image', None),
                command=container.get('command', []),
                environment=container.get('environment', {})
            )

            # Check for errors.
            if "error" in result:
                return result

        return {"success": True}

    def stop_studio(self, name):
        """Stop a studio and all its containers"""
        logger.info(f"Stopping studio {name}")
    
    def list_studios(self):
        """List all studios"""
        logger.info(f"Listing studios")
 