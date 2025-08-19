from collections import deque
import threading
import socket
import struct
import hashlib
import zlib
import logging
import time
import json
import os
import random

import _executor as _executor


## Constants ##

PEER_TTL = 15.0
SCAN_INTERVAL = 1.0
IGMP_INTERVAL = 125.0  # 125s (RFC 2236 (IGMPv2)).
GOSSIP_INTERVAL = 3.0  # Increased from 2.0 to reduce noise
GOSSIP_FANOUT = 3      # Number of peers to gossip to per round
DEPLOY_TTL = 24 * 3600 # Deploy TTL (24 hours)
MAX_UDP = 60000        # UDP packet body limit (60KB)
MAX_GOSSIP_AGE = 30.0  # Maximum age of gossip messages to forward
logger = logging.getLogger(__name__)


## Classes ##

class Runtime():
    """
    Container runtime for distributed container orchestration.

    Handles cluster membership, state synchronization, and deployment propagation
    using efficient gossip-based communication. Each node maintains a view of the 
    cluster and gossips incremental state changes to a subset of peers.

    Example:
        runtime = Runtime()
        runtime.start()
        runtime.stop()
        
    """
    def __init__(self, multicast_addr: str = '239.0.0.2', multicast_port: int = 4242,
                 machine_id: str = open('/etc/machine-id').read().strip()):
        """
        Initialize the Runtime.
        
        Args:
            multicast_addr: Multicast group address for cluster communication.
            multicast_port: UDP port for cluster communication.
            machine_id: Unique identifier for this node.

        Attributes:
            interface: The name of the default network interface used by this node.
            address: The IP address of the default network interface used by this node.
            executor: High-level (CLI) executor to interact with runtime.
            lock: Reentrant lock for thread-safe state changes.
            seq: Local sequence number for state updates.
            local_view: Local containers' state.
            cluster: Known cluster nodes and their state.
            deploys: Active deployments.
            threads: List of threads.
            pending_updates: Queue of pending state updates to gossip.
            seen_messages: Set of seen message IDs to prevent loops.

            _send: UDP socket for sending multicast packets.
        """

        self.multicast_addr = multicast_addr
        self.multicast_port = multicast_port
        self.machine_id = machine_id

        self.interface = Runtime._ifname()
        self.address = Runtime._ipaddr()
        self.executor = _executor.Executor()
        self.lock = threading.RLock()
        self.seq = 0
        self.local_view = {}
        self.cluster = {}
        self.deploys = {}
        
        # Gossip protocol state
        self.pending_updates = deque(maxlen=1000) # Limit memory usage.
        self.seen_messages = set() # Message deduplication.
        self.last_gossip_round = 0 # Last gossip round.
        self.peer_addresses = {} # Map node IDs to addresses.

        self._send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.address))
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) # TTL = 1.
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1) # Loopback.

    @staticmethod
    def _ipaddr() -> str:
        """IP address (4 byte-packed)"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80)) # Doesn't send.
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def _ifname() -> str:
        """Interface name (default route)"""
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                iface, dest, _ = line.split()[:3]
                if dest == "00000000":
                    return iface
        raise RuntimeError("No default route found")

    @staticmethod
    def _checksum(data: bytes) -> int:
        """Checksum function (RFC 1071)"""
        s = 0
        for i in range(0, len(data), 2):
            w = data[i] << 8 | (data[i+1] if i+1 < len(data) else 0)
            s = (s + w) & 0xffffffff
        while (s >> 16):
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff

    @staticmethod
    def _hashsum(msg_type: str, content: dict) -> str:
        """Generate a unique message ID for deduplication"""
        content_str = json.dumps(content, separators=(",", ":"), sort_keys=True)
        return hashlib.blake2b(f"{msg_type}:{content_str}".encode(), digest_size=16).hexdigest()

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

        ifindex = socket.if_nametoindex(self.interface)
        mreqn = struct.pack("4s4si",
            socket.inet_aton(self.multicast_addr),
            socket.inet_aton("0.0.0.0"),
            ifindex
        )
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
        
        s.settimeout(1.0)
        return s

    def _sock_send(self, msg: dict, target_addr: str = None):
        """Send message to specific target or multicast"""
        raw = json.dumps(msg, separators=(",", ":")).encode()
        comp = zlib.compress(raw, 6)
        payload, enc = (comp, "z") if len(comp) <= MAX_UDP else (raw, "raw")
        header = json.dumps({"enc": enc}).encode() + b"\n"
        
        addr = target_addr or self.multicast_addr
        try:
            self._send.sendto(header + payload, (addr, self.multicast_port))
            if target_addr:
                logger.debug(f"Sent direct message: {msg.get('t', 'UNKNOWN')} to {addr}:{self.multicast_port}")
            else:
                logger.debug(f"Sent multicast message: {msg.get('t', 'UNKNOWN')} to {addr}:{self.multicast_port}")
        except Exception as e:
            logger.debug(f"Failed to send message: {e}")

    def _get_random_peers(self, count: int) -> list:
        """Get random subset of known peers for gossip"""
        with self.lock:
            now = time.time()
            active_peers = [
                node_id for node_id, info in self.cluster.items()
                if now - info["ts"] <= PEER_TTL and node_id != self.machine_id
            ]
            
            if len(active_peers) <= count:
                return active_peers
            
            return random.sample(active_peers, count)

    def _detect_changes(self, snapshot: dict) -> list:
        """Detect incremental changes in container state"""
        changes = []
        current_containers = {c.get('id'): c for c in snapshot.get("containers", [])}
        
        with self.lock:
            # Check for new/updated containers
            for container_id, container_info in current_containers.items():
                old_info = self.local_view.get(container_id, {})
                new_state = {
                    "status": container_info.get('status'),
                    "ip_address": container_info.get('ip_address'),
                    "id": container_id,
                    "ver": self.seq + 1
                }
                
                if (old_info.get('status') != new_state['status'] or 
                    old_info.get('ip_address') != new_state['ip_address']):
                    changes.append(('update', container_id, new_state))
                    self.seq += 1
            
            # Check for removed containers
            current_ids = set(current_containers.keys())
            old_ids = set(self.local_view.keys())
            for removed_id in old_ids - current_ids:
                if self.local_view[removed_id].get('status') != 'removed':
                    changes.append(('remove', removed_id, {"status": "removed", "ver": self.seq + 1}))
                    self.seq += 1
        
        return changes

    def _queue_updates(self, changes: list):
        """Queue updates for gossip propagation"""
        with self.lock:
            for change_type, container_id, state in changes:
                # Update local view
                self.local_view[container_id] = state
                
                # Queue for gossip
                update_msg = {
                    "t": "UPDATE",
                    "node": self.machine_id,
                    "container_id": container_id,
                    "state": state,
                    "ts": time.time()
                }
                self.pending_updates.append(update_msg)

    def _gossip_to_peers(self, peers: list):
        """Gossip pending updates to selected peers"""
        if not self.pending_updates:
            return
        
        # Aggregate multiple updates into a single message
        updates = []
        with self.lock:
            while self.pending_updates and len(updates) < 10:  # Limit batch size
                updates.append(self.pending_updates.popleft())
        
        if not updates:
            return
        
        # Send aggregated updates to each peer
        for peer_id in peers:
            peer_addr = self.peer_addresses.get(peer_id)
            if not peer_addr:
                continue
                
            gossip_msg = {
                "t": "GOSSIP",
                "from": self.machine_id,
                "updates": updates,
                "msg_id": Runtime._hashsum("GOSSIP", {"updates": updates}),
                "ts": time.time()
            }
            
            self._sock_send(gossip_msg, peer_addr)

    def _igmp_loop(self):
        """Refresh IGMP membership for the cluster."""
        while True:
            time.sleep(IGMP_INTERVAL)

            IGMP_MEMBERSHIP_QUERY = 0x11 # Membership query.
            MAX_RESP_TIME = 10 # 1s (in 1/10s units).
            IGMP_GROUP = "224.0.0.1" # All-hosts group.

            # Create raw socket for IGMP.
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())

            # Build IGMP query packet.
            igmp_type = IGMP_MEMBERSHIP_QUERY
            max_resp_time = MAX_RESP_TIME
            group_addr = socket.inet_aton("0.0.0.0") # General query.

            pkt = struct.pack("!BBH4s", igmp_type, max_resp_time, 0, group_addr)
            cksum = Runtime._checksum(pkt)
            pkt = struct.pack("!BBH4s", igmp_type, max_resp_time, cksum, group_addr)

            # Destination = all-hosts group.
            dst = (IGMP_GROUP, 0)
            sock.sendto(pkt, dst)

    def _gossip_loop(self):
        """Efficient gossip-based state propagation"""
        while True:
            time.sleep(GOSSIP_INTERVAL)
            
            # Get current state snapshot
            snapshot = self.executor.list_containers()
            if "error" in snapshot:
                continue
            
            # Detect changes and create incremental updates
            changes = self._detect_changes(snapshot)
            if changes:
                self._queue_updates(changes)
            
            # Gossip to random subset of peers
            peers = self._get_random_peers(GOSSIP_FANOUT)
            if peers:
                self._gossip_to_peers(peers)
            
            # Clean up old seen messages (prevent memory leaks)
            now = time.time()
            cutoff = now - MAX_GOSSIP_AGE

            if len(self.seen_messages) > 10000: # Prevent unbounded growth.
                self.seen_messages.clear()

    def _announce_loop(self):
        """Announce heartbeat to the cluster."""
        while True:
            time.sleep(GOSSIP_INTERVAL * 2)  # Less frequent heartbeats
            
            # Send lightweight heartbeat instead of full state
            heartbeat = {
                "t": "HEARTBEAT",
                "node": self.machine_id,
                "addr": self.address,
                "seq": self.seq,
                "ts": time.time()
            }
            
            self._sock_send(heartbeat)

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
                        if n in self.peer_addresses:
                            del self.peer_addresses[n]
                for d in list(self.deploys.keys()):
                    if self.deploys[d]["ts"] < dep_cut:
                        del self.deploys[d]

    def _receive_loop(self):
        """Receive messages from the cluster"""
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
            
            # Handle different message types
            t = msg.get("t")
            if t == "GOSSIP":
                self._handle_gossip(msg)
            elif t == "HEARTBEAT":
                self._handle_heartbeat(msg)
            elif t == "DEPLOY":
                self.deploy(msg)

    def _handle_gossip(self, msg: dict):
        """Handle incoming gossip messages"""
        msg_id = msg.get("msg_id")
        if not msg_id or msg_id in self.seen_messages:
            return  # Already seen this message
        
        self.seen_messages.add(msg_id)
        
        # Process updates
        updates = msg.get("updates", [])
        with self.lock:
            for update in updates:
                container_id = update.get("container_id")
                state = update.get("state")
                source_node = update.get("node")
                
                if source_node and source_node != self.machine_id:
                    # Update cluster view
                    if source_node not in self.cluster:
                        self.cluster[source_node] = {"containers": {}, "ts": time.time()}
                    
                    self.cluster[source_node]["containers"][container_id] = state
                    self.cluster[source_node]["ts"] = time.time()
        
        # Forward to other peers (with some probability to prevent flooding)
        if random.random() < 0.3: # 30% chance to forward.
            peers = self._get_random_peers(GOSSIP_FANOUT - 1)
            for peer_id in peers:
                if peer_id != msg.get("from"):
                    peer_addr = self.peer_addresses.get(peer_id)
                    if peer_addr:
                        self._sock_send(msg, peer_addr)

    def _handle_heartbeat(self, msg: dict):
        """Handle heartbeat messages for membership"""
        node_id = msg.get("node")
        if not node_id or node_id == self.machine_id:
            return
        
        now = time.time()
        with self.lock:
            if node_id not in self.cluster:
                self.cluster[node_id] = {"containers": {}, "ts": now}
            
            self.cluster[node_id]["ts"] = now
            self.cluster[node_id]["addr"] = msg.get("addr")
            self.peer_addresses[node_id] = msg.get("addr")

    def _merge_state(self, msg: dict):
        """Legacy state merge - kept for compatibility"""
        # This is now handled by _handle_gossip
        pass

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

        # Only stop containers that are part of deployments but shouldn't be here
        # Don't stop manually started containers that aren't part of any deployment
        current = set([k for k, v in self.local_view.items() if v["status"] != "removed"])
        
        # Only consider containers that are part of deployments for stopping
        deployment_containers = set()
        for identifier, deployment in self.deploys.items():
            for name in deployment.get("services", {}).keys():
                deployment_containers.add(name)
        
        # Only stop containers that are part of deployments but not wanted here
        containers_to_stop = (current & deployment_containers) - want_here
        
        for cname in containers_to_stop:
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

    def _reconcile_loop(self):
        """Periodic reconciliation to ensure state consistency"""
        while True:
            time.sleep(10)  # Run every 10 seconds
            self._reconcile_state()

    def start(self):
        """Start the runtime"""
        threading.Thread(target=self._igmp_loop, daemon=True).start()
        threading.Thread(target=self._gossip_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()
        threading.Thread(target=self._receive_loop, daemon=True).start()
        threading.Thread(target=self._purge_loop, daemon=True).start()
        threading.Thread(target=self._reconcile_loop, daemon=True).start()