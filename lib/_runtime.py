import subprocess
import threading
import socket
import fcntl
import struct
import hashlib
import zlib
import logging
import time
import json
import os
import re

import _executor as _executor


## Constants ##

PEER_TTL = 15.0
SCAN_INTERVAL = 1.0
ANNOUNCE_INTERVAL = 2.0
DEPLOY_TTL = 24 * 3600 # Deploy TTL (24 hours)
MAX_UDP = 60000 # UDP packet body limit
logger = logging.getLogger(__name__)


## Classes ##

class Runtime():
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
            executor: High-level (CLI) executor to interact with runtime.
            lock: Reentrant lock for thread-safe state changes.
            seq: Local sequence number for state updates.
            local_view: Local containers' state.
            cluster: Known cluster nodes and their state.
            deploys: Active deployments.
            threads: List of threads.

            _send: UDP socket for sending multicast packets.
        """

        self.multicast_addr = multicast_addr
        self.multicast_port = multicast_port
        self.machine_id = machine_id
        self.interface = interface
        
        self.address = self._ip(interface)
        self.executor = _executor.Executor()
        self.lock = threading.RLock()
        self.seq = 0
        self.local_view = {}
        self.cluster = {}
        self.deploys = {}
        self.threads = []

        self._send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self._ip("clearly0")))
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

    @staticmethod
    def _ip(ifname: str) -> bytes:
        """IP address retrieval function"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915, # SIOCGIFADDR
            struct.pack('256s', ifname.encode('utf-8')[:15])
        )[20:24])

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
        mreq = struct.pack("4s4s", socket.inet_aton(self.multicast_addr), socket.inet_aton(self._ip("clearly0")))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.settimeout(1.0)
        return s

    def _sock_send(self, msg: dict):
        """Send multicast message to the cluster"""
        raw = json.dumps(msg, separators=(",", ":")).encode()
        comp = zlib.compress(raw, 6)
        payload, enc = (comp, "z") if len(comp) <= MAX_UDP else (raw, "raw")
        header = json.dumps({"enc": enc}).encode() + b"\n"
        try:
            self._send.sendto(header + payload, (self.multicast_addr, self.multicast_port))
            logger.info(f"Sent multicast message: {msg.get('t', 'UNKNOWN')} to {self.multicast_addr}:{self.multicast_port}")
        except Exception:
            pass

    def _announce_loop(self):
        """Announce the local view to the cluster"""
        last_hash = None
        while True:
            time.sleep(ANNOUNCE_INTERVAL)
            snapshot = self.executor.list_containers()
            if "error" in snapshot:
                continue
            
            hash_data = []
            for container in snapshot.get("containers"):
                hash_data.append(f"{container.get('id')}:{container.get('ip_address')}:{container.get('status')}")

            h = hashlib.blake2b("|".join(hash_data).encode(), digest_size=8).hexdigest()
            if h != last_hash:
                self.seq += 1
                with self.lock:
                    for container in snapshot.get("containers"):
                        self.local_view[container.get('id')] = {
                            "status": container.get('status'),
                            "ip_address": container.get('ip_address'),
                            "id": container.get('id'),
                            "ver": self.seq
                        }
                    
                    for k in [k for k in list(self.local_view.keys()) if k not in [container.get('id') for container in snapshot.get("containers")]]:
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
                    self.executor.start_container(
                        name=name,
                        image=spec["image"],
                        command=spec["command"],
                        publish=spec["publish"],
                        environment=spec["environment"]
                    )

        current = set([k for k, v in self.local_view.items() if v["status"] != "removed"])

        for cname in current - want_here:
            self.executor.stop_container(cname)

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