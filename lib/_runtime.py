import subprocess
import threading
import logging
import time
import json
import os
import re

import _proxy as _proxy


## Constants ##

PEER_TTL = 15.0
SCAN_INTERVAL = 1.0
ANNOUNCE_INTERVAL = 2.0
DEPLOY_TTL = 24 * 3600 # Deploy TTL (24 hours)
MAX_UDP = 60000 # UDP packet body limit
logger = logging.getLogger(__name__)


## Classes ##

class Runtime(BaseRuntime):
    """
    Container runtime for distributed container orchestration.

    Handles cluster membership, state synchronization, and deployment propagation
    using UDP multicast. Each node maintains a view of the cluster and periodically
    announces its state.

    Example:
        runtime = Runtime(
            multicast_addr='239.42.0.1',
            multicast_port=4243,
            machine_id=open('/etc/machine-id').read().strip(),
            address='192.168.1.100'
        )
        runtime.start()
        runtime.stop()
        
    """
    def __init__(self, multicast_addr: str = '239.42.0.1', multicast_port: int = 4243,
                 machine_id: str = open('/etc/machine-id').read().strip(), interface: str = 'clearly0'):
        """
        Initialize the Runtime.
        
        Args:
            multicast_addr: Multicast group address for cluster communication.
            multicast_port: UDP port for cluster communication.
            machine_id: Unique identifier for this node (default: read from /etc/machine-id).
            interface: The network interface used by this node.

        Attributes:
            address: The IP address of the network interface used by this node.
            lock: Reentrant lock for thread-safe state changes.
            seq: Local sequence number for state updates.
            local_view: Local containers' state.
            cluster: Known cluster nodes and their state.
            deploys: Active deployments.
            threads: List of threads.

            _send: UDP socket for sending multicast packets.
        """
        super().__init__()

        self.multicast_addr = multicast_addr
        self.multicast_port = multicast_port
        self.machine_id = machine_id
        self.interface = interface
        
        self.address = self._ip(interface)
        self.lock = threading.RLock()
        self.seq = 0
        self.local_view = {}
        self.cluster = {}
        self.deploys = {}
        self.threads = []

        self._send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

    @staticmethod
    def _ip(ifname: str) -> str:
        """IP address (as 4-byte packed format)"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return fcntl.ioctl(
            s.fileno(),
            0x8915, # SIOCGIFADDR
            struct.pack('256s', ifname.encode('utf-8')[:15])
        )[20:24]

    @staticmethod
    def _blake64(b: bytes) -> int:
        """Blake2b hash function"""
        return int.from_bytes(hashlib.blake2b(b, digest_size=8).digest(), "big", signed=False)

    @staticmethod
    def _hrw_topk(key: bytes, nodes: list, k: int) -> list:
        """HRW top-k algorithm"""
        scored = [(Runtime._blake64(key + n.encode()), n) for n in nodes]
        scored.sort(reverse=True)
        return [n for _, n in scored[:max(1, min(k, len(scored)))]]

    def _sock_recv(self) -> socket.socket:
        """Create a socket for receiving multicast messages"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", self.multicast_port))
        except OSError:
            s.bind((self.multicast_addr, self.multicast_port))
        mreq = struct.pack("=4sl", socket.inet_aton(self.multicast_addr), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.settimeout(1.0)
        return s

    def _sock_send(self, msg: dict):
        """Announce a message to the cluster"""
        raw = json.dumps(msg, separators=(",", ":")).encode()
        comp = zlib.compress(raw, 6)
        payload, enc = (comp, "z") if len(comp) <= MAX_UDP else (raw, "raw")
        header = json.dumps({"enc": enc}).encode() + b"\n"
        try:
            self._send.sendto(header + payload, (self.multicast_addr, self.multicast_port))
        except Exception:
            pass

    def _announce_loop(self):
        """Announce the local view to the cluster"""
        last_hash = None
        while True:
            time.sleep(ANNOUNCE_INTERVAL)
            snapshot = self.runtime.list_containers()
            if "error" in snapshot:
                continue
            
            hash_data = []
            for k, v in sorted(snapshot.get("containers", {}).items()):
                hash_data.append(f"{k}:{v.get('status', 'unknown')}:{v.get('ip_address', '')}:{v.get('id', '')}")
            
            h = hashlib.blake2b("|".join(hash_data).encode(), digest_size=8).hexdigest()
            if h != last_hash:
                self.seq += 1
                with self.lock:
                    for k, v in snapshot.get("containers", {}).items():
                        prev = self.local_view.get(k)
                        if not prev or prev.get("status") != v.get("status"):
                            self.local_view[k] = {
                                "status": v.get("status", "unknown"),
                                "ip_address": v.get("ip_address", ""),
                                "id": v.get("id", ""),
                                "ver": self.seq
                            }
                    
                    for k in [k for k in list(self.local_view.keys()) if k not in snapshot.get("containers", {})]:
                        self.seq += 1
                        self.local_view[k] = {"status": "removed", "ver": self.seq}
                last_hash = h
            with self.lock:
                items = sorted(self.local_view.items(), key=lambda kv: kv[1]["ver"], reverse=True)
                delta = dict(items[:400])

            self._sock_send({
                "t": "STATE",
                "node": self.machine_id,
                "addr": self.address,
                "seq": self.seq,
                "delta": delta,
                "ts": time.time()
            })

    def _purge_loop(self):
        """Purge expired nodes and deployments"""
        while True:
            time.sleep(5)
            cut = time.time() - PEER_TTL
            dep_cut = time.time() - DEPLOY_TTL
            with self.lock:
                for n in list(self.cluster.keys()):
                    if self.cluster[n]["ts"] < cut:
                        del self.cluster[n]
                for d in list(self.deploys.keys()):
                    if self.deploys[d]["ts"] < dep_cut:
                        del self.deploys[d]

    def _receive_loop(self):
        """Receive multicast messages from the cluster"""
        r = self._sock_recv()
        while True:
            try:
                pkt, _ = r.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                header, body = pkt.split(b"\n", 1)
                enc = json.loads(header.decode()).get("enc", "z")
                raw = zlib.decompress(body) if enc == "z" else body
                msg = json.loads(raw.decode())
            except Exception:
                continue
            t = msg.get("t")
            if t == "STATE":
                self._merge_state(msg)
            elif t == "DEPLOY":
                self.deploy(msg)

    def _merge_state(self, msg: dict):
        """Merge the state of a node into the local view"""
        n = msg.get("node")
        if not n or n == self.machine_id:
            return
        now = time.time()
        with self.lock:
            ent = self.cluster.setdefault(n, {"seq": 0, "containers": {}, "ts": now, "addr": msg.get("addr"), "http": msg.get("http")})
            ent["ts"] = now
            ent["addr"] = msg.get("addr")
            ent["http"] = msg.get("http")
            ent["seq"] = max(ent["seq"], int(msg.get("seq", 0)))
            for name, v in msg.get("delta", {}).items():
                cur = ent["containers"].get(name)
                if (not cur) or int(v["ver"]) > int(cur["ver"]):
                    ent["containers"][name] = v

    def _reconcile_state(self):
        """Reconcile the local view with the cluster state"""
        rows = []
        want_here = set()
        nodes = self.list_nodes()
        with self.lock:
            for identifier, deployment in self.deploys.items():
                for name, service in deployment["services"].items():

                    replicas = int(service.get("deploy", {}).get("replicas", 1))
                    base_key = f"{identifier}:{name}".encode()

                    chosen = self._hrw_topk(base_key, nodes, replicas)
                    if not chosen:
                        continue

                    for i in range(replicas):
                        owner = chosen[i % len(chosen)]
                        spec = {
                            "replica": i,
                            "identifier": identifier,
                            "image": service.get("image"),
                            "command": service.get("command", []),
                            "publish": service.get("ports", []),
                            "environment": service.get("environment", {}),
                        }

                        rows.append((owner, name, spec))

        for owner, name, spec in rows:
            if owner == self.machine_id:
                want_here.add(name)
                if name not in self.local_view or self.local_view.get(name, {}).get("status") == "stopped":
                    self.runtime.start_container(
                        name=name,
                        image=spec["image"],
                        command=spec["command"],
                        publish=spec["publish"],
                        environment=spec["environment"]
                    )

        current = set([k for k, v in self.local_view.items() if v["status"] != "removed"])

        for cname in current - want_here:
            self.runtime.stop_container(cname)

    def list_nodes(self) -> list:
        """List all nodes in the cluster"""
        with self.lock:
            ids = [self.machine_id]
            now = time.time()
            for n, m in self.cluster.items():
                if now - m["ts"] <= PEER_TTL:
                    ids.append(n)
        return sorted(set(ids))

    def deploy(self, msg: dict):
        """Deploy a group of containers"""
        dep = msg.get("deploy") or {}
        dep_id = dep.get("id")
        if not dep_id:
            return
        with self.lock:
            self.deploys[dep_id] = {"ts": time.time(), "services": dep.get("services", [])}
        self._reconcile_state()

    def start(self):
        """Start the runtime"""
        self.threads = [
            threading.Thread(target=self._announce_loop, daemon=True),
            threading.Thread(target=self._receive_loop, daemon=True),
            threading.Thread(target=self._purge_loop, daemon=True),
        ]
        for t in self.threads:
            t.start()

    def stop(self):
        """Stop the runtime"""
        for t in self.threads:
            t.join()
        self.threads = []

class BaseRuntime(Runtime):
    """BaseRuntime"""

    def __init__(self):
        pass

    def start_container(self, name: str, image: str, command: list,
                        publish: dict, environment: dict) -> dict:
        """Start a container"""
        try:
            cmd = ["clearly", "run", image, "--name", name, "--detach"]

            if publish:
                for key, value in publish.items():
                    cmd.extend(["--publish", f"{key}:{value}"])
            
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

    
# class StudioExecutor(Executor):
#     """StudioExecutor"""
# 
#     def __init__(self):
#         super().__init__()
# 
#     def start_studio(self, name):
#         """Start a studio, which is a group of containers"""
# 
#         containers = [
#             {
#                 "name": "vscode",
#                 "image": "codercom/code-server:4.101.2-39",
#                 "command": ["/usr/bin/entrypoint.sh", "--bind-addr", "0.0.0.0:8080", ".", "--auth", "none"],
#                 "proxy": { "0": "8080" }
#             },
#             {
#                 "name": "jupyter",
#                 "image": "jupyter/minimal-notebook:python-3.9.13",
#                 "command": [
#                     "tini", "-g", "--", "start-notebook.sh",
#                     "--ServerApp.token=",
#                     "--ServerApp.password=",
#                     "--ServerApp.allow_origin=*",
#                     "--ServerApp.disable_check_xsrf=True",
#                     "--ServerApp.tornado_settings={\"headers\":{\"Content-Security-Policy\":\"frame-ancestors *\"}}"
#                 ],
#                 "proxy": { "0": "8888" }
#             }
#         ]
#         
#         # Start all containers.
#         for container in containers:
#             result = self.start_container(
#                 name=f"~{name}-{container['name']}",
#                 image=container.get('image', None),
#                 command=container.get('command', []),
#                 environment=container.get('environment', {})
#             )
# 
#             # Check for errors.
#             if "error" in result:
#                 return result
# 
#         return {"success": True}
# 
#     def stop_studio(self, name):
#         """Stop a studio and all its containers"""
#         logger.info(f"Stopping studio {name}")
#     
#     def list_studios(self):
#         """List all studios"""
#         logger.info(f"Listing studios")
# 