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
import fcntl

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
                 machine_id: str = open('/etc/machine-id').read().strip(), bridge: str = "clearly0"):
        """
        Initialize the Runtime.
        
        Args:
            multicast_addr: Multicast group address for cluster communication.
            multicast_port: UDP port for cluster communication.
            machine_id: Unique identifier for this node.
            bridge: Bridge interface name.
        """

        self.multicast_addr = multicast_addr
        self.multicast_port = multicast_port
        self.machine_id = machine_id
        self.bridge = bridge

        # Runtime state.
        self.interface = Runtime._ifname()
        self.address = Runtime._ipaddr()
        self.executor = _executor.Executor()
        self.lock = threading.RLock()
        self.seq = 0
        self.local = {}
        self.cluster = {}
        self.deploys = {}
        
        # Gossip protocol state.
        self.message_queue = deque(maxlen=1000) # Limit memory usage.
        self.seen_messages = set() # Message deduplication.
        self.last_gossip_round = 0 # Last gossip round.
        self.peer_addresses = {} # Map node IDs to addresses.
        self.deployment_plans = {} # Map deployment IDs to plans.
        self.ip_reservations = {} # Map IP addresses to reservations.

        # Multicast socket.
        self._send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.address))
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0) # Disable Loopback.
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) # TTL = 1.

    """ Getters """

    @property
    def nodes(self) -> list:
        """List all nodes in the cluster"""
        with self.lock:
            ids = [self.machine_id]
            now = time.time()
            for n, m in self.cluster.items():
                if now - m["ts"] <= PEER_TTL:
                    ids.append(n)
        return sorted(set(ids))

    """ Static """

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

    @staticmethod
    def _get_if_mac(ifname: str) -> bytes:
        """Read interface MAC address as 6 bytes."""
        try:
            with open(f"/sys/class/net/{ifname}/address", "r") as f:
                mac_str = f.read().strip()
            return bytes(int(x, 16) for x in mac_str.split(":"))
        except Exception:
            return b"\x00\x00\x00\x00\x00\x00"

    @staticmethod
    def _get_if_ipv4(ifname: str) -> str:
        """Get IPv4 address for interface (best-effort)."""
        SIOCGIFADDR = 0x8915
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ifreq = struct.pack('256s', ifname.encode('utf-8')[:15])
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
            ip = socket.inet_ntoa(res[20:24])
            return ip
        except Exception:
            return "0.0.0.0"
        finally:
            s.close()

    @staticmethod
    def _arp_is_free(ip: str, ifname: str, retries: int = 2, timeout: float = 0.2) -> bool:
        """Send ARP who-has for ip on interface and return True if no reply received."""
        target_ip = socket.inet_aton(ip)
        src_mac = Runtime._get_if_mac(ifname)
        src_ip = socket.inet_aton(Runtime._get_if_ipv4(ifname))

        # Ethernet frame header
        eth_dst = b"\xff\xff\xff\xff\xff\xff" # Destination MAC address (broadcast).
        eth_src = src_mac                     # Source MAC address.
        eth_type = struct.pack('!H', 0x0806)  # EtherType (ARP).

        # ARP payload (request)
        htype = struct.pack('!H', 1)          # Hardware type (Ethernet).
        ptype = struct.pack('!H', 0x0800)     # Protocol type (IPv4).
        hlen  = struct.pack('!B', 6)          # Hardware address length.
        plen  = struct.pack('!B', 4)          # Protocol address length.
        oper  = struct.pack('!H', 1)          # ARP operation (request).
        sha   = src_mac                       # Source hardware address.
        spa   = src_ip                        # Source protocol address.
        tha   = b"\x00" * 6                   # Target hardware address.
        tpa   = target_ip                     # Target protocol address.
        arp_payload = b"".join([htype, ptype, hlen, plen, oper, sha, spa, tha, tpa])
        frame = eth_dst + eth_src + eth_type + arp_payload

        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            s.settimeout(timeout)
            s.bind((ifname, 0))
        except Exception as e:
            logger.warning(f"ARP: Failed to create socket: {e}")
            return False

        try:
            for _ in range(retries):
                try:
                    s.send(frame)
                except Exception:
                    pass
                try:
                    while True:
                        pkt = s.recv(65535)
                        if len(pkt) < 42:
                            continue
                        # EtherType.
                        if pkt[12:14] != b"\x08\x06":
                            continue
                        # ARP op.
                        op = struct.unpack('!H', pkt[20:22])[0]
                        if op != 2: # Reply.
                            continue
                        spa_reply = pkt[28:32]
                        if spa_reply == target_ip:
                            return False # IP is in use.
                except socket.timeout:
                    # No reply observed.
                    pass
            return True
        finally:
            s.close()

    @staticmethod
    def _virtual_mac_for_ip(ip: str) -> bytes:
        """Derive a stable, locally administered unicast MAC from an IP string."""
        h = hashlib.blake2b(ip.encode(), digest_size=6).digest()
        first = (h[0] & 0b11111100) | 0b00000010 # local admin, unicast
        return bytes([first]) + h[1:6]

    @staticmethod
    def _deterministic_ip(dep_id: str, service: str, replica: int) -> str:
        """Generate a deterministic IP within 10.0.0.0/8 avoiding .0 and .255 last octet."""
        seed = f"{dep_id}:{service}:{replica}".encode()
        h = hashlib.blake2b(seed, digest_size=4).digest()
        a = 10
        b = h[0]
        c = h[1]
        # map last octet to 2..254
        d = (h[2] % 253) + 2
        return f"{a}.{b}.{c}.{d}"

    @staticmethod
    def _candidate_ip(dep_id: str, service: str, replica: int, salt: int) -> str:
        seed = f"{dep_id}:{service}:{replica}:{salt}".encode()
        h = hashlib.blake2b(seed, digest_size=4).digest()
        a = 10
        b = h[0]
        c = h[1]
        d = (h[2] % 253) + 2
        return f"{a}.{b}.{c}.{d}"

    @staticmethod
    def _socket_receive(address: str, port: int, via_address: str) -> socket.socket:
        """Create a socket for receiving multicast messages"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", port))

        mreq = struct.pack("4s4s", socket.inet_aton(address), socket.inet_aton(via_address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        sock.settimeout(1.0)
        return sock

    @staticmethod
    def _socket_send(socket: socket.socket, message: dict, address: str, port: int) -> None:
        """Send message to specific target or multicast"""
        raw = json.dumps(message, separators=(",", ":")).encode()
        comp = zlib.compress(raw, 6)
        payload, enc = (comp, "z") if len(comp) <= MAX_UDP else (raw, "raw")
        header = json.dumps({"enc": enc}).encode() + b"\n"
        
        try:
            socket.sendto(header + payload, (address, port))
        except Exception as e:
            logger.warning(f"Failed to send message: {e}")

    """ Helpers """

    def _reserve_ip(self, ip: str, dep_id: str, service: str, replica: int, ttl: float = 120.0):
        now = time.time()
        with self.lock:
            self.ip_reservations[ip] = {"node": self.machine_id, "dep": dep_id, "service": service, "replica": replica, "ts": now, "ttl": ttl}
        message = {
            "t": "RESERVE_IP",
            "ip": ip,
            "dep": dep_id,
            "service": service,
            "replica": replica,
            "node": self.machine_id,
            "ttl": ttl,
            "ts": now,
            "id": Runtime._hashsum("RESERVE_IP", {"ip": ip, "dep": dep_id, "service": service, "replica": replica})
        }
        Runtime._socket_send(
            socket=self._send,
            message=message,
            address=self.multicast_addr,
            port=self.multicast_port
        )

    def _get_plan(self, dep: dict) -> dict:
        """Build a deterministic plan assigning replicas to nodes and IPs.

        Returns a dict: { service: { replica_index: {"node": node_id, "ip": ip, "name": cname }}}
        """
        plan = {}
        services = dep.get("services", {}) or {}

        # Build a plan for each service.
        for name, service in services.items():
            replicas = int(service.get("deploy", {}).get("replicas", 1))
            base_key = f"{dep.get('id')}:{name}".encode()
            chosen_nodes = self._hrw_topk(base_key, self.nodes, max(1, replicas)) or []
            plan[name] = {}
            for i in range(replicas):
                owner = chosen_nodes[i % len(chosen_nodes)] if chosen_nodes else self.machine_id
                cname = name if replicas == 1 else f"{name}-{i}"
                # Find an available IP: prefer deterministic, fallback with salted candidates
                sel_ip = None
                for salt in range(0, 64):
                    cand = Runtime._candidate_ip(dep.get("id"), name, i, salt)
                    with self.lock:
                        reserved = self.ip_reservations.get(cand)
                    if reserved and reserved.get("node") != self.machine_id:
                        continue
                    if not Runtime._arp_is_free(cand, self.bridge):
                        continue
                    sel_ip = cand
                    break
                if sel_ip is None:
                    # As a last resort, pick deterministic without checking to proceed
                    sel_ip = Runtime._deterministic_ip(dep.get("id"), name, i)

                # Reserve chosen IP (best-effort)
                self._reserve_ip(sel_ip, dep.get("id"), name, i)

                plan[name][i] = {
                    "node": owner,
                    "ip": sel_ip,
                    "name": cname,
                }
        return plan

    def _get_random(self, count: int) -> list:
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

    """ Loops """

    def _arp_loop(self):
        """Respond to ARP requests for reserved IPs so others see them as taken."""
        iface = "clearly0" if os.path.exists("/sys/class/net/clearly0") else self.interface
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            s.bind((iface, 0))
        except Exception as e:
            logger.warning(f"ARP responder disabled (raw socket error): {e}")
            return
        while True:
            try:
                pkt = s.recv(65535)
            except Exception:
                continue
            # Minimum ARP over Ethernet frame size
            if len(pkt) < 42:
                continue
            # EtherType ARP
            if pkt[12:14] != b"\x08\x06":
                continue
            # Parse ARP request
            arp = pkt[14:]
            if len(arp) < 28:
                continue
            op = struct.unpack("!H", arp[6:8])[0]
            if op != 1:
                continue
            sha = arp[8:14]
            spa = arp[14:18]
            tha = arp[18:24]
            tpa = arp[24:28]
            target_ip = socket.inet_ntoa(tpa)
            with self.lock:
                reserved = self.ip_reservations.get(target_ip)
            if not reserved:
                continue
            # Craft reply
            src_mac = Runtime._virtual_mac_for_ip(target_ip)
            eth = sha           # dest = sender MAC.
            eth += src_mac      # src = our virtual mac.
            eth += b"\x08\x06"  # EtherType ARP.
            htype = b"\x00\x01" # Ethernet.
            ptype = b"\x08\x00" # IPv4.
            hlen = b"\x06"      # Hardware address length.
            plen = b"\x04"      # Protocol address length.
            oper = b"\x00\x02"  # ARP operation (reply).
            spa_reply = tpa     # sender protocol address.
            tpa_reply = spa     # target protocol address.
            tha_reply = sha     # sender hardware address.
            arp_reply = htype + ptype + hlen + plen + oper + src_mac + spa_reply + tha_reply + tpa_reply
            frame = eth + arp_reply
            try:
                s.send(frame)
            except Exception:
                pass

    def _igmp_loop(self):
        """Refresh IGMP membership for the cluster."""
        while True:
            time.sleep(IGMP_INTERVAL)

            IGMP_MEMBERSHIP_QUERY = 0x11 # Membership query.
            MAX_RESP_TIME = 10           # 1s (in 1/10s units).
            IGMP_GROUP = "224.0.0.1"     # All-hosts group.

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
            
            # Get current state snapshot.
            snapshot = self.executor.list_containers()
            if "error" in snapshot:
                continue
            
            # Detect incremental changes in container state.
            changes = []
            with self.lock:
                # Check for new/updated containers
                containers = {c.get('id'): c for c in snapshot.get("containers", [])}
                for container_id, container_info in containers.items():
                    old_info = self.local.get(container_id, {})
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
                current_ids = set(containers.keys())
                old_ids = set(self.local.keys())
                for removed_id in old_ids - current_ids:
                    if self.local[removed_id].get('status') != 'removed':
                        changes.append(('remove', removed_id, {"status": "removed", "ver": self.seq + 1}))
                        self.seq += 1

            # Update local view and queue for gossip.
            if changes:
                with self.lock:
                    for change_type, container_id, state in changes:
                        # Update local view
                        self.local[container_id] = state
                        
                        # Queue for gossip
                        update_msg = {
                            "t": "UPDATE",
                            "node": self.machine_id,
                            "container_id": container_id,
                            "state": state,
                            "ts": time.time()
                        }
                        self.message_queue.append(update_msg)
            
            # Gossip to random subset of peers.
            peers = self._get_random(GOSSIP_FANOUT)
            if peers and self.message_queue:
                # Aggregate multiple updates into a single message
                updates = []
                with self.lock:
                    while self.message_queue and len(updates) < 10:  # Limit batch size
                        updates.append(self.message_queue.popleft())
                
                if not updates:
                    return
                
                # Send aggregated updates to each peer
                for peer_id in peers:
                    peer_addr = self.peer_addresses.get(peer_id)
                    if not peer_addr:
                        continue
                        
                    message = {
                        "t": "GOSSIP",
                        "from": self.machine_id,
                        "updates": updates,
                        "id": Runtime._hashsum("GOSSIP", {"updates": updates}),
                        "ts": time.time()
                    }
                    
                    Runtime._socket_send(
                        socket=self._send,
                        message=message,
                        address=peer_addr,
                        port=self.multicast_port
                    )
            
            # Clean up old seen messages (prevent memory leaks).
            now = time.time()
            cutoff = now - MAX_GOSSIP_AGE

            # Prevent unbounded growth.
            if len(self.seen_messages) > 10000: 
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
            
            Runtime._socket_send(
                socket=self._send,
                message=heartbeat,
                address=self.multicast_addr,
                port=self.multicast_port
            )

    def _purge_loop(self):
        """Purge expired nodes and deployments"""
        while True:
            time.sleep(5)
            cut = time.time() - PEER_TTL
            dep_cut = time.time() - DEPLOY_TTL
            with self.lock:
                # Purge expired nodes.
                for n in list(self.cluster.keys()):
                    if self.cluster[n]["ts"] < cut:
                        del self.cluster[n]
                        if n in self.peer_addresses:
                            del self.peer_addresses[n]

                # Purge expired deployments.
                for d in list(self.deploys.keys()):
                    if self.deploys[d]["ts"] < dep_cut:
                        del self.deploys[d]

                # Purge expired IP reservations.
                now = time.time()
                for ip in list(self.ip_reservations.keys()):
                    entry = self.ip_reservations.get(ip)
                    if not entry:
                        continue
                    if now - entry.get("ts", 0) > entry.get("ttl", 120.0):
                        del self.ip_reservations[ip]

    def _receive_loop(self):
        """Receive messages from the cluster"""
        r = self._socket_receive(self.multicast_addr, self.multicast_port, self.address)
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
            except Exception as e:
                logger.warning(f"Failed to parse message: {e}")
                continue
            
            # Handle different message types
            t = msg.get("t")
            if t == "GOSSIP":
                self._handle_gossip(msg)
            elif t == "HEARTBEAT":
                self._handle_heartbeat(msg)
            elif t == "DEPLOY":
                id = msg.get("id")
                if id and id in self.seen_messages:
                    continue
                if id:
                    self.seen_messages.add(id)
                self.deploy(msg)
            elif t == "RESERVE_IP":
                id = msg.get("id")
                if id and id in self.seen_messages:
                    continue
                if id:
                    self.seen_messages.add(id)
                ip = msg.get("ip")
                ttl = float(msg.get("ttl", 120.0))
                if not ip:
                    continue
                with self.lock:
                    current = self.ip_reservations.get(ip)
                    # Only record if unreserved or same owner; ignore conflicting owners
                    if not current or current.get("node") == msg.get("node"):
                        self.ip_reservations[ip] = {
                            "node": msg.get("node"),
                            "dep": msg.get("dep"),
                            "service": msg.get("service"),
                            "replica": msg.get("replica"),
                            "ts": time.time(),
                            "ttl": ttl,
                        }

    def _reconcile_loop(self):
        """Periodic reconciliation to ensure state consistency"""
        while True:
            time.sleep(10)
            self._handle_reconcile()

    """ Handlers """

    def _handle_gossip(self, message: dict):
        """Handle incoming gossip messages"""
        id = message.get("id")
        if not id or id in self.seen_messages:
            return # Already seen this message
        
        self.seen_messages.add(id)
        
        # Process updates
        updates = message.get("updates", [])
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
            peers = self._get_random(GOSSIP_FANOUT - 1)
            for peer_id in peers:
                if peer_id != message.get("from"):
                    peer_addr = self.peer_addresses.get(peer_id)
                    if peer_addr:
                        Runtime._socket_send(
                            socket=self._send,
                            message=message,
                            address=peer_addr,
                            port=self.multicast_port
                        )

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

    def _handle_reconcile(self):
        """Reconcile the local view with the cluster state"""
        rows = []
        want_here = set()

        # Build a local plan for each deployment.
        with self.lock:
            for id, deployment in self.deploys.items():
                    services = deployment.get("services", {})
                    plan = deployment.get("plan")
                    if plan is None:
                        # Fallback: Construct a local plan (not broadcasted).
                        plan = self._get_plan({"id": id, "services": services})
                        deployment["plan"] = plan

                    for name, replicas in plan.items():
                        service = services.get(name, {})
                        for i, spec_plan in replicas.items():
                            owner = spec_plan.get("node")
                            spec = {
                                "id": id,
                                "replica": i,
                                "image": service.get("image"),
                                "command": service.get("command", []),
                                "publish": service.get("ports", []),
                                "environment": service.get("environment", {}),
                                "ip": spec_plan.get("ip"),
                                "name": spec_plan.get("name") or (name if len(replicas) == 1 else f"{name}-{i}")
                            }
                            rows.append((owner, name, spec))

            # Start containers.
            for owner, name, spec in rows:
                if owner == self.machine_id:
                    cname = f"{spec.get('id')}_{spec.get('name')}"
                    want_here.add(cname)
                    if cname not in self.local or self.local.get(cname, {}).get("status") == "stopped":
                        plan = None
                        allow = []

                        # Get deployment plan for this container.
                        with self.lock:
                            plan = self.deploys.get(spec["id"], {}).get("plan")

                        # Build allow list from entire deployment plan.
                        for _svc, replicas in plan.items():
                            for _i, spec_plan in replicas.items():
                                ip = spec_plan.get("ip")
                                if ip and ip != spec.get("ip"):
                                    allow.append(ip)

                        # Start container.
                        self.executor.start_container(
                            name=cname,
                            image=spec.get("image"),
                            command=spec.get("command", []),
                            publish=spec.get("publish", []),
                            environment=spec.get("environment", {}),
                            ip=spec.get("ip"),
                            allow=allow
                        )

            # Only stop containers that are part of deployments but shouldn't be here
            # Don't stop manually started containers that aren't part of any deployment
            current = set([k for k, v in self.local.items() if v["status"] != "removed"])
            
            # Only consider containers that are part of deployments for stopping
            deployment_containers = set()
            for _, deployment in self.deploys.items():
                plan = deployment.get("plan")
                services = deployment.get("services", {})
                if plan:
                    for name, replicas in plan.items():
                        for i, spec_plan in replicas.items():
                            deployment_containers.add(spec_plan.get("name") or (name if len(replicas) == 1 else f"{name}-{i}"))
                else:
                    for name in services.keys():
                        deployment_containers.add(name)
            
            # Only stop containers that are part of deployments but not wanted here
            containers_to_stop = (current & deployment_containers) - want_here
            
            for cname in containers_to_stop:
                self.executor.stop_container(cname)

    """ Main """

    def deploy(self, msg: dict):
        """Deploy a group of containers"""
        deployment = msg.get("deploy") or {}
        plan = msg.get("plan")

        # If no plan provided, originate a plan and broadcast once.
        if plan is None:
            plan = self._get_plan(deployment)
            message = {
                "t": "DEPLOY",
                "deploy": deployment,
                "plan": plan,
                "ts": time.time(),
                "id": Runtime._hashsum(
                    "DEPLOY", {"deploy": deployment}
                )
            }

            Runtime._socket_send(
                socket=self._send,
                message=message,
                address=self.multicast_addr,
                port=self.multicast_port
            )

        with self.lock:
            self.deploys[deployment.get("id")] = {
                "ts": time.time(),
                "services": deployment.get("services", {}),
                "plan": plan
            }

        # Reconcile.
        self._handle_reconcile()

    def start(self):
        """Start the runtime"""
        threading.Thread(target=self._arp_loop, daemon=True).start()
        threading.Thread(target=self._igmp_loop, daemon=True).start()
        threading.Thread(target=self._gossip_loop, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()
        threading.Thread(target=self._receive_loop, daemon=True).start()
        threading.Thread(target=self._reconcile_loop, daemon=True).start()
        threading.Thread(target=self._purge_loop, daemon=True).start()