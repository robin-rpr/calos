/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include <linux/netfilter/nf_tables.h>
#include <linux/if_packet.h>
#include <linux/if_bridge.h>
#include <linux/if_arp.h>
#include <linux/filter.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/addr.h>
#include <libnl3/netlink/route/route.h>
#include <libnl3/netlink/route/link/veth.h>
#include <libnl3/netlink/route/link/vxlan.h>
#include <libnl3/netlink/route/link/bridge.h>

#include "misc.h"
#include "link.h"


/** Macros **/

/* <linux/netfilter.h> */
#define NF_DROP   0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE  3
#define NF_REPEAT 4

#define NFPROTO_UNSPEC  0
#define NFPROTO_INET    1
#define NFPROTO_IPV4    2
#define NFPROTO_ARP     3
#define NFPROTO_NETDEV  5
#define NFPROTO_BRIDGE  7
#define NFPROTO_IPV6   10
#define NFPROTO_DECNET 12

#define NF_INET_PRE_ROUTING  0
#define NF_INET_LOCAL_IN     1
#define NF_INET_FORWARD      2
#define NF_INET_LOCAL_OUT    3
#define NF_INET_POST_ROUTING 4
#define NF_INET_NUMHOOKS     5
#define NF_INET_INGRESS      5

/* <linux/netfilter_bridge.h> */
#define NF_BR_PRE_ROUTING  0
#define NF_BR_LOCAL_IN     1
#define NF_BR_FORWARD      2
#define NF_BR_LOCAL_OUT    3
#define NF_BR_POST_ROUTING 4
#define NF_BR_BROUTING     5
#define NF_BR_NUMHOOKS     6

/* <linux/netfilter_ipv4.h> */
#define NF_IP_PRE_ROUTING  0
#define NF_IP_POST_ROUTING 4


/** Functions **/

/* Send an ARP probe to a given IP address.

    This function will send an ARP probe to a given target IP address
    via the provided bridge interface.

    Return values:
        0: IP address is available
        1: IP address is taken
        -1: Error
*/
int send_arp(const struct in_addr *target_ip, const char *bridge_name, struct in_addr *bridge_ip) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd == -1) { perror("socket"); return -1; }

    /*
     * BPF filter to only accept ARP replies.
     * This prevents the socket from receiving its own outgoing ARP requests
     * and other irrelevant traffic.
    */
    struct sock_filter arp_reply_filter[] = {
        // Must be an ARP packet
        { 0x28, 0, 0, 0x0000000c }, // ldh [12]
        { 0x15, 0, 1, 0x00000806 }, // jne #0x806, drop
        // Must be an ARP reply (opcode 2)
        { 0x30, 0, 0, 0x00000014 }, // ldb [20]
        { 0x15, 0, 1, 0x00000002 }, // jne #0x2, drop
        // It's an ARP reply, accept it
        { 0x6, 0, 0, 0x00040000 },  // ret #262144
        // Not an ARP reply, drop it
        { 0x6, 0, 0, 0x00000000 }   // ret #0
    };

    struct sock_fprog bpf = {
        .len = sizeof(arp_reply_filter) / sizeof(struct sock_filter),
        .filter = arp_reply_filter,
    };

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) == -1) {
        perror("setsockopt BPF");
        close(sockfd);
        return -1;
    }

    // Define the structure of the ARP payload
    struct arp_payload {
        unsigned char sender_mac[ETH_ALEN];
        uint32_t      sender_ip;
        unsigned char target_mac[ETH_ALEN];
        uint32_t      target_ip;
    } __attribute__((packed));

    struct sockaddr_ll sock_addr;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bridge_name, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) { perror("SIOCGIFINDEX"); close(sockfd); return -1; }
    sock_addr.sll_ifindex = ifr.ifr_ifindex;
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) { perror("SIOCGIFHWADDR"); close(sockfd); return -1; }

    // Total size of ARP request: Ethernet header + ARP header + ARP payload
    unsigned char arp_request[sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arp_payload)];
    struct ethhdr *eth_hdr = (struct ethhdr *)arp_request;
    struct arphdr *arp_hdr = (struct arphdr *)(arp_request + sizeof(struct ethhdr));
    struct arp_payload *arp_data = (struct arp_payload *)(arp_request + sizeof(struct ethhdr) + sizeof(struct arphdr));

    // Ethernet Header
    memset(eth_hdr->h_dest, 0xFF, ETH_ALEN); // Broadcast MAC
    memcpy(eth_hdr->h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_ARP);

    // ARP Header
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);  // Hardware type: Ethernet
    arp_hdr->ar_pro = htons(ETH_P_IP);      // Protocol type: IP
    arp_hdr->ar_hln = ETH_ALEN;             // Hardware address length: 6 bytes (MAC)
    arp_hdr->ar_pln = 4;                    // Protocol address length: 4 bytes (IP)
    arp_hdr->ar_op = htons(ARPOP_REQUEST);  // Operation: ARP Request

    // ARP Payload
    memcpy(arp_data->sender_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    memcpy(&arp_data->sender_ip, bridge_ip, sizeof(*bridge_ip));
    memset(arp_data->target_mac, 0x00, ETH_ALEN); // Target MAC unknown (0s for request)
    memcpy(&arp_data->target_ip, target_ip, sizeof(*target_ip));

    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_protocol = htons(ETH_P_ARP);
    sock_addr.sll_hatype = ARPHRD_ETHER;
    sock_addr.sll_pkttype = PACKET_BROADCAST;
    sock_addr.sll_halen = ETH_ALEN;
    memset(sock_addr.sll_addr, 0xFF, ETH_ALEN); // Broadcast to all

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 }; // 1 second timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    if (sendto(sockfd, arp_request, sizeof(arp_request), 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        perror("sendto"); close(sockfd); return -1;
    }

    unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arp_payload)];
    ssize_t bytes_received;

    while (1) {
        bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes_received == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) { 
                // Timeout, IP is likely available.
                close(sockfd);
                return 0;
            } 
            perror("recvfrom"); close(sockfd); return -1;
        }

        if (bytes_received < (ssize_t)(sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arp_payload))) {
            // Received packet is too small to be a complete ARP reply.
            continue;
        }

        struct ethhdr *rcv_eth_hdr = (struct ethhdr *)buffer;
        struct arphdr *rcv_arp_hdr = (struct arphdr *)(buffer + sizeof(struct ethhdr));
        struct arp_payload *reply_payload = (struct arp_payload *)(buffer + sizeof(struct ethhdr) + sizeof(struct arphdr));

        if (ntohs(rcv_eth_hdr->h_proto) == ETH_P_ARP && ntohs(rcv_arp_hdr->ar_op) == ARPOP_REPLY) {
            struct in_addr reply_ip;
            memcpy(&reply_ip, &reply_payload->sender_ip, sizeof(reply_ip));
            if (reply_ip.s_addr == target_ip->s_addr) {
                // IP is alredy taken.
                close(sockfd);
                return 1;
            }
        }
    }
}

/* Return true if a link exists. */
bool is_link_exists(const char *link_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    struct rtnl_link *link;
    if (rtnl_link_get_kernel(sock, 0, link_name, &link) < 0) {
        VERBOSE("link '%s' not found", link_name);
        nl_socket_free(sock);
        return false;
    } else {
        VERBOSE("link '%s' found", link_name);
        rtnl_link_put(link);
        nl_socket_free(sock);
        return true;
    }
}

/* Create a new network bridge.

   This function will create a bridge, and configure it with
   the given IP Address and 32-bit CIDR.

       1. Allocate a bridge link, set the name, type, and flags.
       2. Send the bridge link to the linux kernel.
       3. Configure the IP Address & 32-bit CIDR.

    The assumption is that the bridge doesn't already exist.
    If it does, this function will fail.
*/
void create_bridge(const char *bridge_name, const struct in_addr *ip, int cidr) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Allocate a bridge link.
    // Set the name, type, and flags (IFF_UP).
    struct rtnl_link *bridge = rtnl_link_bridge_alloc();
    Tf(bridge != NULL, "failed to allocate bridge link");

    rtnl_link_set_name(bridge, bridge_name);
    rtnl_link_set_family(bridge, AF_BRIDGE);
    rtnl_link_set_type(bridge, "bridge");
    rtnl_link_set_flags(bridge, IFF_UP);

    Zf(rtnl_link_add(sock, bridge, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK) < 0,
       "failed to create bridge '%s'", bridge_name);
    rtnl_link_put(bridge);

    // Retrieve the new bridge link.
    // Get the link again to configure it.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, bridge_name, &link) < 0,
       "failed to get new bridge link '%s'", bridge_name);
    int if_index = rtnl_link_get_ifindex(link);
    rtnl_link_put(link);

    // Configure the IP Address & CIDR.
    // Allocate an address, set the local IP address, and set the ifindex.
    struct rtnl_addr *addr = rtnl_addr_alloc();
    Tf(addr != NULL, "failed to allocate 'address'");
    char ip_str[INET_ADDRSTRLEN + 4]; // +4 for slash + 32-bit CIDR.
    struct nl_addr *local_ip;
    
    snprintf(ip_str, sizeof(ip_str), "%s/%d", inet_ntoa(*ip), cidr); 

    Zf(nl_addr_parse(ip_str, AF_INET, &local_ip) < 0, "failed to parse address %s", ip_str);
    rtnl_addr_set_local(addr, local_ip);
    nl_addr_put(local_ip);

    rtnl_addr_set_ifindex(addr, if_index);

    Zf(rtnl_addr_add(sock, addr, 0) < 0, "failed to add address to bridge '%s'", bridge_name);

    rtnl_addr_put(addr);

    // Free the socket.
    VERBOSE("bridge '%s' created and configured", bridge_name);
    nl_socket_free(sock);
}

/* Return true if a bridge exists. */
bool is_bridge_exists(const char *bridge_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");
    
    struct rtnl_link *link;
    if (rtnl_link_get_kernel(sock, 0, bridge_name, &link) < 0) {
        VERBOSE("bridge '%s' not found", bridge_name);
        nl_socket_free(sock);
        return false;
    } else {
        VERBOSE("bridge '%s' found", bridge_name);
        rtnl_link_put(link);
        nl_socket_free(sock);
        return true;
    }
}

/* Create a new veth pair.

   This function will create a veth pair, and configure it with
   the given host and peer names.

   1. Allocate a veth link, set the name.
   2. Allocate a peer link for the veth link, set the name.
   3. Send the veth link to the linux kernel.

   The assumption is that the veth pair doesn't already exist.
   If it does, this function will fail.
*/
void create_veth_pair(const char *host_name, const char *peer_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Allocate a veth link.
    // This creates the primary veth link.
    struct rtnl_link *veth = rtnl_link_veth_alloc();
    Tf(veth != NULL, "failed to allocate veth link");
    rtnl_link_set_name(veth, host_name);

    // Allocate a peer link for the veth link.
    // This creates the peer link that is connected to the veth link.
    struct rtnl_link *peer = rtnl_link_veth_get_peer(veth);
    rtnl_link_set_name(peer, peer_name);

    // Send the veth link to the linux kernel.
    Zf(rtnl_link_add(sock, veth, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK) < 0,
       "failed to create veth pair ('%s', '%s')", host_name, peer_name);

    rtnl_link_put(veth);

    // Free the socket.
    VERBOSE("veth pair ('%s', '%s') created", host_name, peer_name);
    nl_socket_free(sock);
}

/* Attach a veth to a bridge. */
void set_veth_bridge(const char *veth_name, const char *bridge_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth and bridge links.
    struct rtnl_link *link, *bridge;
    Zf(rtnl_link_get_kernel(sock, 0, veth_name, &link) < 0, "failed to get link '%s'", veth_name);
    Zf(rtnl_link_get_kernel(sock, 0, bridge_name, &bridge) < 0, "failed to get bridge '%s'", bridge_name);

   // Clone the link so we can modify it.
   struct rtnl_link *link_change = rtnl_link_alloc();
   Zf(link_change == NULL, "failed to allocate link");

   rtnl_link_set_ifindex(link_change, rtnl_link_get_ifindex(link));
   rtnl_link_set_master(link_change, rtnl_link_get_ifindex(bridge));
   
   rtnl_link_set_flags(link_change, IFF_UP);

   // Send the link change to the kernel.
   Zf(rtnl_link_change(sock, link, link_change, 0) < 0,
    "failed to attach '%s' to bridge '%s'", veth_name, bridge_name);

   rtnl_link_put(link_change);
   rtnl_link_put(link);
   rtnl_link_put(bridge);

   // Free the socket.
    VERBOSE("veth '%s' attached to bridge '%s'", veth_name, bridge_name);
    nl_socket_free(sock);
}

/* Bring up a veth. */
void set_veth_up(const char *veth_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, veth_name, &link) < 0, "failed to get link '%s'", veth_name);

   // Clone the link so we can modify it.
   struct rtnl_link *link_change = rtnl_link_alloc();
   Zf(link_change == NULL, "failed to allocate link");

   // Set the ifindex and flags (IFF_UP).
   rtnl_link_set_ifindex(link_change, rtnl_link_get_ifindex(link));   
   rtnl_link_set_flags(link_change, IFF_UP);

   // Send the link change to the kernel.
   Zf(rtnl_link_change(sock, link, link_change, 0) < 0, "failed to bring up '%s'", veth_name);

   rtnl_link_put(link_change);
   rtnl_link_put(link);

   // Free the socket.
    VERBOSE("veth '%s' brought up", veth_name);
    nl_socket_free(sock);
}

/* Set a veth to a given name. */
void set_veth_name(const char *veth_name, const char *new_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, veth_name, &link) < 0, "failed to get link '%s'", veth_name);

   // Clone the link so we can modify it.
   struct rtnl_link *link_change = rtnl_link_alloc();
   Zf(link_change == NULL, "failed to allocate link");

   // Set the ifindex and new name.
   rtnl_link_set_ifindex(link_change, rtnl_link_get_ifindex(link));   
   rtnl_link_set_name(link_change, new_name);
    
   // Send the link change to the kernel.
   Zf(rtnl_link_change(sock, link, link_change, 0) < 0, "failed to rename '%s' to '%s'", veth_name, new_name);

   rtnl_link_put(link_change);
   rtnl_link_put(link);

   // Free the socket.
   VERBOSE("veth '%s' renamed to '%s'", veth_name, new_name);
   nl_socket_free(sock);
}

/* Set a veth default route. */
void set_veth_route(const char *veth_name, const struct in_addr *gateway, const char *destination) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, veth_name, &link) < 0, "failed to get link '%s'", veth_name);

    // Allocate a route.
    struct rtnl_route *route_change = rtnl_route_alloc();
    Tf(route_change != NULL, "failed to allocate 'route'");
        
    // Parse the route destination.
    struct nl_addr *destination_addr;
    Zf(nl_addr_parse(destination, AF_INET, &destination_addr) < 0, "failed to parse route destination");
    Zf(rtnl_route_set_dst(route_change, destination_addr) < 0, "failed to set route destination");
    nl_addr_put(destination_addr);

    // Parse the gateway address.
    struct nl_addr *gateway_addr;
    Zf(nl_addr_parse(inet_ntoa(*gateway), AF_INET, &gateway_addr) < 0, "failed to parse gateway address");

    // Allocate a nexthop.
    struct rtnl_nexthop *nexthop = rtnl_route_nh_alloc();
    Tf(nexthop != NULL, "failed to allocate 'nexthop'");
    rtnl_route_nh_set_ifindex(nexthop, rtnl_link_get_ifindex(link));
    rtnl_route_nh_set_gateway(nexthop, gateway_addr);
    rtnl_route_add_nexthop(route_change, nexthop);
    nl_addr_put(gateway_addr);

    // Send the route change to the kernel.
    Zf(rtnl_route_add(sock, route_change, 0) < 0, "failed to add default route to '%s'", veth_name);

    rtnl_route_put(route_change);
    rtnl_link_put(link);

   // Free the socket.
   VERBOSE("veth '%s' default route set to '%s' via '%s'", veth_name, destination, inet_ntoa(*gateway));
   nl_socket_free(sock);
}

/* Set a veth to a given IP address. */
void set_veth_ip(const char *veth_name, const struct in_addr *ip, int cidr) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, veth_name, &link) < 0, "failed to get link '%s'", veth_name);

    // Allocate an address.
    struct rtnl_addr *addr_change = rtnl_addr_alloc();
    Tf(addr_change != NULL, "failed to allocate 'address'");
    struct nl_addr *parsed_ip;

    char ip_str[INET_ADDRSTRLEN + 4];
    snprintf(ip_str, sizeof(ip_str), "%s/%d", inet_ntoa(*ip), cidr);

    // Parse the IP address.
    Zf(nl_addr_parse(ip_str, AF_INET, &parsed_ip) < 0, "failed to parse ip address");
    rtnl_addr_set_local(addr_change, parsed_ip);
    nl_addr_put(parsed_ip);

    // Set the ifindex and IP address.
    rtnl_addr_set_ifindex(addr_change, rtnl_link_get_ifindex(link));

    // Send the address change to the kernel.
    Zf(rtnl_addr_add(sock, addr_change, 0) < 0, "failed to add address to veth '%s'", veth_name);

    rtnl_addr_put(addr_change);
    rtnl_link_put(link);

    // Free the socket.
    VERBOSE("veth '%s' IP address set to '%s'", veth_name, ip_str);
    nl_socket_free(sock);
}

/* Set a veth to a network namespace of a given pid. */
void set_veth_ns_pid(const char *link_name, pid_t pid) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link and its ifindex.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, link_name, &link) < 0, "failed to get link '%s'", link_name);
    int if_index = rtnl_link_get_ifindex(link);
    Zf(if_index <= 0, "invalid ifindex for link '%s'", link_name);

    // Clone the link so we can modify it.
    struct rtnl_link *link_change = rtnl_link_alloc();
    Tf(link_change != NULL, "failed to allocate link");

    // Set the ifindex and network namespace pid.
    rtnl_link_set_ifindex(link_change, if_index);
    rtnl_link_set_ns_pid(link_change, pid);

    // Send the link change to the kernel.
    Zf(rtnl_link_add(sock, link_change, NLM_F_ACK) < 0, "failed to move link '%s' to pid", link_name, pid);

    rtnl_link_put(link_change);
    rtnl_link_put(link);

    // Free the socket.
    VERBOSE("veth '%s' set to network namespace of pid %d", link_name, pid);
    nl_socket_free(sock);
}

/* Set a random MAC address for a veth */
void set_veth_mac(const char *veth_name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    Tf(fd >= 0, "failed to create socket for ioctl");

    // Seed the random number generator.
    srand(time(NULL) ^ getpid());

    // Allocate a MAC address.
    struct ifreq ifr = {0};
    unsigned char mac[6];

    // Set the locally administered unicast bit.
    mac[0] = 0x02; 
    for (int i = 1; i < 6; i++) {
        // Generate and apply a random MAC address.
        mac[i] = rand() % 256;
    }

    strncpy(ifr.ifr_name, veth_name, IFNAMSIZ); // Copy the veth name to the ifreq struct.
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER; // Ethernet hardware address family.
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6); // 6 bytes for the MAC address
    Zf(ioctl(fd, SIOCSIFHWADDR, &ifr), "ioctl(SIOCSIFHWADDR) failed for %s", veth_name);

    // Close the socket.
    VERBOSE("set MAC address for %s to %02x:%02x:%02x:%02x:%02x:%02x", veth_name,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    close(fd);
}

/* Create a SNAT (Source NAT) masquerade. 

   This function will create a SNAT masquerade rule for the specified subnet.

   1. Create the 'nat' table.
   2. Create the 'postrouting' chain.
   3. Create an empty 'rule'.
   4. Create a match 'expr'ession for the subnet.
   5. Create a 'bitwise' allocation for the CIDR.
   6. Create a comparison 'expr'ession for the subnet.
   7. Create the 'masq' expression.
   8. Send the rule to the kernel.

   The assumption is that the masquerade rule doesn't already exist.
   If it does, this function will fail.
*/
void create_nft_masquerade(const struct in_addr *subnet, int cidr) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "Failed to open netlink socket for masquerade");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for masquerade");

    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    uint32_t seq = time(NULL);

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    struct nlmsghdr *nlh;

    // Create the 'nat' table.
    struct nftnl_table *table = nftnl_table_alloc();
    Tf(table != NULL, "failed to allocate 'table'");
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, "nat");
    nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                     NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    // Create the 'postrouting' chain.
    struct nftnl_chain *chain = nftnl_chain_alloc();
    Tf(chain != NULL, "failed to allocate 'chain'");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, "nat");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, "postrouting");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "nat");
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_IP_POST_ROUTING);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 100); // SNAT priority
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_POLICY, NF_ACCEPT);

    nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                      NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
                                      NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    nftnl_chain_free(chain);
    mnl_nlmsg_batch_next(batch);

    // Create an empty 'rule'.
    struct nftnl_rule *rule = nftnl_rule_alloc();
    Tf(rule != NULL, "failed to allocate 'rule'");
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "postrouting");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    // Create a match 'expr'ession for the subnet.
    struct nftnl_expr *match;
    match = nftnl_expr_alloc("payload");
    Tf(match != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, match);

    // Create a 'bitwise' allocation for the CIDR.
    uint32_t mask = htonl(0xFFFFFFFF << (32 - cidr));
    match = nftnl_expr_alloc("bitwise");
    Tf(match != NULL, "failed to allocate 'bitwise' expression");
    nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
    nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
    nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_LEN, sizeof(uint32_t));
    nftnl_expr_set_data(match, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
    uint32_t zero = 0;
    nftnl_expr_set_data(match, NFTNL_EXPR_BITWISE_XOR, &zero, sizeof(zero));
    nftnl_rule_add_expr(rule, match);

    // Create a comparison 'expr'ession for the subnet.
    match = nftnl_expr_alloc("cmp");
    Tf(match != NULL, "failed to allocate 'cmp' expression");
    nftnl_expr_set_u32(match, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(match, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(match, NFTNL_EXPR_CMP_DATA, &subnet->s_addr, sizeof(subnet->s_addr));
    nftnl_rule_add_expr(rule, match);

    // Create the 'masq' expression.
    struct nftnl_expr *expr = nftnl_expr_alloc("masq");
    Tf(expr != NULL, "failed to allocate 'masq' expression");
    nftnl_rule_add_expr(rule, expr);

    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWRULE, NFPROTO_IPV4,
                                     NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule);
    mnl_nlmsg_batch_next(batch);

    // Close the batch.
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // Send the batch to the kernel
    if (mnl_socket_sendto(sock, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
      Zf(1, "kernel rejected masquerade rule");
      mnl_socket_close(sock);
      return;
    }

    // Free the socket.
    VERBOSE("nftables masquerade created for subnet %s/%d", inet_ntoa(*subnet), cidr);
    mnl_socket_close(sock);
}

/* Check if the SNAT masquerade rule exists. */
bool is_nft_masquerade_exists(const struct in_addr *subnet) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "Failed to open netlink socket for masquerade");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for masquerade");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);

    // Request dump of all rules
    struct nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_IPV4, NLM_F_DUMP, seq);

    struct nftnl_rule *req = nftnl_rule_alloc();
    Tf(req != NULL, "failed to allocate 'rule'");
    nftnl_rule_set_str(req, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(req, NFTNL_RULE_CHAIN, "postrouting");
    nftnl_rule_nlmsg_build_payload(nlh, req);
    nftnl_rule_free(req);

    Zf(mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0, "send failed");

    int len = mnl_socket_recvfrom(sock, buf, sizeof(buf));
    if (len == 0) return false;
    while (len > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        for (; mnl_nlmsg_ok(nlh, len); nlh = mnl_nlmsg_next(nlh, &len)) {
            // Check if the message is a new rule.
            if (nlh->nlmsg_type != ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE)) continue;

            struct nftnl_rule *rule = nftnl_rule_alloc();
            Tf(rule != NULL, "failed to allocate 'rule'");
            nftnl_rule_nlmsg_parse(nlh, rule);

            const char *table = nftnl_rule_get_str(rule, NFTNL_RULE_TABLE);
            const char *chain = nftnl_rule_get_str(rule, NFTNL_RULE_CHAIN);
            if (!table || !chain || strcmp(table, "nat") != 0 || strcmp(chain, "postrouting") != 0) {
                nftnl_rule_free(rule);
                continue;
            }

            bool has_payload = false, has_bitwise = false, has_cmp = false, has_masq = false;
            uint32_t cmp_val = 0;

            struct nftnl_expr_iter *it = nftnl_expr_iter_create(rule);
            struct nftnl_expr *expr;
            while ((expr = nftnl_expr_iter_next(it)) != NULL) {
                const char *name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
                if (!name) continue;

                if (strcmp(name, "payload") == 0) {
                    has_payload = true;
                } else if (strcmp(name, "bitwise") == 0) {
                    has_bitwise = true;
                } else if (strcmp(name, "cmp") == 0) {
                    uint32_t data_len = 0;
                     const void *data = nftnl_expr_get_data(expr, NFTNL_EXPR_CMP_DATA, &data_len);
                     if (data && data_len == sizeof(uint32_t)) {
                        memcpy(&cmp_val, data, sizeof(cmp_val));
                        has_cmp = true;
                     }
                } else if (strcmp(name, "masq") == 0) {
                    has_masq = true;
                }
            }

            nftnl_expr_iter_destroy(it);
            nftnl_rule_free(rule);

            if (has_payload && has_bitwise && has_cmp && has_masq) {
                if (cmp_val == subnet->s_addr) {
                    mnl_socket_close(sock);
                    return true;
                }
            }
        }

        if (len == 0) {
            mnl_socket_close(sock);
            return false;
        }
    }

    mnl_socket_close(sock);
    return false;
}

/* Create a DNAT (Destination NAT) filter.

    This function creates a filter rule that drops all traffic that is not
    within the specified subnet.

    1. Create the 'filter' table.
    2. Create the 'forward' chain.
    3. Create the default drop rule for container-to-container traffic.
    4. Send the batch command to the kernel.

    The assumption is that the subnet is a private subnet, and that the
    rules doesn't already exist.
 */
void create_nft_filter(const struct in_addr *subnet, int cidr) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "Failed to open netlink socket for filter");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for filter");

    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    uint32_t seq = time(NULL);

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    struct nlmsghdr *nlh;

    // Create the 'filter' table.
    struct nftnl_table *table = nftnl_table_alloc();
    Tf(table != NULL, "failed to allocate 'filter' table");
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_BRIDGE);
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, "filter");
    nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_BRIDGE,
                                     NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    // Create the 'forward' chain.
    struct nftnl_chain *chain = nftnl_chain_alloc();
    Tf(chain != NULL, "failed to allocate 'forward' chain");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, "filter");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, "forward");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "filter");
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_BR_FORWARD);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 0);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_POLICY, NF_ACCEPT); // Default policy is accept.

    nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                      NFT_MSG_NEWCHAIN, NFPROTO_BRIDGE,
                                      NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    nftnl_chain_free(chain);
    mnl_nlmsg_batch_next(batch);

    // Create the default drop rule for container-to-container traffic.
    struct nftnl_rule *rule = nftnl_rule_alloc();
    Tf(rule != NULL, "failed to allocate 'default drop' rule");
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "filter");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "forward");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_BRIDGE);

    struct nftnl_expr *expr;

    // Load the Ethernet type into NFT_REG_1
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "failed to allocate 'payload' expression for eth_type");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_LL_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, 12);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint16_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    // Compare NFT_REG_1 to ETH_P_IP
    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "failed to allocate 'cmp' expression for eth_type");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    uint16_t eth_ip = htons(ETH_P_IP);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &eth_ip, sizeof(eth_ip));
    nftnl_rule_add_expr(rule, expr);

    // Match source address within the subnet
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    uint32_t mask = htonl(0xFFFFFFFF << (32 - cidr));
    expr = nftnl_expr_alloc("bitwise");
    Tf(expr != NULL, "failed to allocate 'bitwise' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, sizeof(uint32_t));
    nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
    uint32_t zero = 0;
    nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_XOR, &zero, sizeof(zero));
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "failed to allocate 'cmp' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &subnet->s_addr, sizeof(subnet->s_addr));
    nftnl_rule_add_expr(rule, expr);

    // Match destination address within the subnet
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, daddr));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1); // Can reuse REG_1
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("bitwise");
    Tf(expr != NULL, "failed to allocate 'bitwise' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, sizeof(uint32_t));
    nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
    nftnl_expr_set_data(expr, NFTNL_EXPR_BITWISE_XOR, &zero, sizeof(zero));
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "failed to allocate 'cmp' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &subnet->s_addr, sizeof(subnet->s_addr));
    nftnl_rule_add_expr(rule, expr);

    // Immediate: Drop
    expr = nftnl_expr_alloc("immediate");
    Tf(expr != NULL, "failed to allocate 'immediate' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, NF_DROP);
    nftnl_rule_add_expr(rule, expr);

    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWRULE, NFPROTO_BRIDGE,
                                     NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (mnl_socket_sendto(sock, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
      Zf(1, "kernel rejected filter rule");
      mnl_socket_close(sock);
      return;
    }

    VERBOSE("nftables filter created for subnet %s/%d", inet_ntoa(*subnet), cidr);
    mnl_socket_close(sock);
}

/* Check if the container-to-container filter drop rule exists. */
bool is_nft_filter_exists(const struct in_addr *subnet) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "Failed to open netlink socket for filter check");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for filter check");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);

    struct nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_BRIDGE, NLM_F_DUMP, seq);
    struct nftnl_rule *req = nftnl_rule_alloc();
    Tf(req != NULL, "failed to allocate 'rule'");
    nftnl_rule_set_str(req, NFTNL_RULE_TABLE, "filter");
    nftnl_rule_set_str(req, NFTNL_RULE_CHAIN, "forward");
    nftnl_rule_nlmsg_build_payload(nlh, req);
    nftnl_rule_free(req);

    if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
        mnl_socket_close(sock);
        return false;
    }

    int len;
    while ((len = mnl_socket_recvfrom(sock, buf, sizeof(buf))) > 0) {
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        for (; mnl_nlmsg_ok(h, len); h = mnl_nlmsg_next(h, &len)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
                 mnl_socket_close(sock);
                 return false;
            }
            if (h->nlmsg_type != ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE)) continue;

            struct nftnl_rule *rule = nftnl_rule_alloc();
            Tf(rule != NULL, "failed to allocate 'rule'");
            nftnl_rule_nlmsg_parse(h, rule);

            if (nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY) != NFPROTO_BRIDGE) {
                nftnl_rule_free(rule);
                continue;
            }

            int saddr_matched = 0;
            int daddr_matched = 0;
            bool has_drop_verdict = false;
            
            struct nftnl_expr_iter *it = nftnl_expr_iter_create(rule);
            struct nftnl_expr *expr;
            while ((expr = nftnl_expr_iter_next(it)) != NULL) {
                const char *name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
                if (!name) continue;

                if (strcmp(name, "payload") == 0) {
                    uint32_t offset = nftnl_expr_get_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET);
                    if (offset == offsetof(struct iphdr, saddr)) saddr_matched = 1;
                    else if (offset == offsetof(struct iphdr, daddr)) daddr_matched = 1;
                } else if (strcmp(name, "bitwise") == 0) {
                    if (saddr_matched == 1) saddr_matched = 2;
                    if (daddr_matched == 1) daddr_matched = 2;
                } else if (strcmp(name, "cmp") == 0) {
                    uint32_t data_len = 0;
                    const void *data = nftnl_expr_get_data(expr, NFTNL_EXPR_CMP_DATA, &data_len);
                    if (data && data_len == sizeof(uint32_t) && memcmp(data, &subnet->s_addr, sizeof(uint32_t)) == 0) {
                        if (saddr_matched == 2) saddr_matched = 3;
                        if (daddr_matched == 2) daddr_matched = 3;
                    }
                } else if (strcmp(name, "immediate") == 0) {
                    if (nftnl_expr_get_u32(expr, NFTNL_EXPR_IMM_VERDICT) == NF_DROP) has_drop_verdict = true;
                }
            }
            nftnl_expr_iter_destroy(it);
            nftnl_rule_free(rule);

            if (saddr_matched == 3 && daddr_matched == 3 && has_drop_verdict) {
                mnl_socket_close(sock);
                return true;
            }
        }
    }

    mnl_socket_close(sock);
    return false;
}

/* Set a filter allow rule for specific source and destination IPs. */
void set_nft_filter_allow(const struct in_addr *src_ip, const struct in_addr *dst_ip) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "Failed to open netlink socket for filter allow");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for filter allow");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    struct nlmsghdr *nlh;

    struct nftnl_rule *rule = nftnl_rule_alloc();
    Tf(rule != NULL, "failed to allocate 'rule'");
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "filter");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "forward");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_BRIDGE);

    struct nftnl_expr *expr;

    // Load the Ethernet type into NFT_REG_1
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "failed to allocate 'payload' expression for eth_type");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_LL_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, 12);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint16_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    // Compare NFT_REG_1 to ETH_P_IP
    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "failed to allocate 'cmp' expression for eth_type");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    uint16_t eth_ip = htons(ETH_P_IP);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &eth_ip, sizeof(eth_ip));
    nftnl_rule_add_expr(rule, expr);

    // Match source IP
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "failed to allocate 'cmp' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &src_ip->s_addr, sizeof(src_ip->s_addr));
    nftnl_rule_add_expr(rule, expr);

    // Match destination IP
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, daddr));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1); // Reuse REG_1
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "failed to allocate 'cmp' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &dst_ip->s_addr, sizeof(dst_ip->s_addr));
    nftnl_rule_add_expr(rule, expr);

    // Immediate: Accept
    expr = nftnl_expr_alloc("immediate");
    Tf(expr != NULL, "failed to allocate 'immediate' expression");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, NF_ACCEPT);
    nftnl_rule_add_expr(rule, expr);

    // Insert the rule at the beginning of the chain.
    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWRULE, NFPROTO_BRIDGE,
                                     NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (mnl_socket_sendto(sock, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
      Zf(1, "kernel rejected filter allow rule");
      mnl_socket_close(sock);
      return;
    }

    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    VERBOSE("nftables filter allow rule created for %s -> %s",
            inet_ntop(AF_INET, src_ip, src_buf, sizeof(src_buf)),
            inet_ntop(AF_INET, dst_ip, dst_buf, sizeof(dst_buf)));
    mnl_socket_close(sock);
}

/* Flush all filter allow rules involving a specific IP address. */
void flush_nft_filter(const struct in_addr *ip_to_flush) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "failed to open netlink socket for filter flush");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "failed to bind socket for filter flush");

    char get_buf[MNL_SOCKET_BUFFER_SIZE];
    char del_buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t get_seq = time(NULL);

    struct nlmsghdr *nlh_get = nftnl_nlmsg_build_hdr(
        get_buf, NFT_MSG_GETRULE, NFPROTO_BRIDGE, NLM_F_DUMP | NLM_F_ACK, get_seq);
    struct nftnl_rule *rule_template = nftnl_rule_alloc();
    Tf(rule_template != NULL, "failed to allocate rule template");
    nftnl_rule_set_str(rule_template, NFTNL_RULE_TABLE, "filter");
    nftnl_rule_set_str(rule_template, NFTNL_RULE_CHAIN, "forward");
    nftnl_rule_nlmsg_build_payload(nlh_get, rule_template);
    nftnl_rule_free(rule_template);

    if (mnl_socket_sendto(sock, nlh_get, nlh_get->nlmsg_len) < 0) {
        mnl_socket_close(sock);
        return;
    }

    struct mnl_nlmsg_batch *del_batch = mnl_nlmsg_batch_start(del_buf, sizeof(del_buf));
    uint32_t del_seq = time(NULL);
    int delete_count = 0;

    nftnl_batch_begin(mnl_nlmsg_batch_current(del_batch), del_seq++);
    mnl_nlmsg_batch_next(del_batch);

    int ret;
    char recv_buf[MNL_SOCKET_BUFFER_SIZE];
    bool done = false;

    while (!done && (ret = mnl_socket_recvfrom(sock, recv_buf, sizeof(recv_buf))) > 0) {
        struct nlmsghdr *nlh;
        int remaining_len = ret;

        for (nlh = (struct nlmsghdr *)recv_buf; mnl_nlmsg_ok(nlh, remaining_len); nlh = mnl_nlmsg_next(nlh, &remaining_len)) {
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }

            if (nlh->nlmsg_type != ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE)) continue;

            struct nftnl_rule *rule = nftnl_rule_alloc();
            Tf(rule != NULL, "failed to allocate rule for parsing");
            if (nftnl_rule_nlmsg_parse(nlh, rule) < 0) {
                nftnl_rule_free(rule);
                continue;
            }

            if (nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY) != NFPROTO_BRIDGE) {
                nftnl_rule_free(rule);
                continue;
            }

            bool is_accept_rule = false;
            bool ip_is_involved = false;
            
            struct nftnl_expr_iter *iter = nftnl_expr_iter_create(rule);
            struct nftnl_expr *expr;

            while ((expr = nftnl_expr_iter_next(iter)) != NULL) {
                const char *expr_name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
                if (!expr_name) continue;

                if (strcmp(expr_name, "immediate") == 0) {
                    if (nftnl_expr_get_u32(expr, NFTNL_EXPR_IMM_VERDICT) == NF_ACCEPT) {
                        is_accept_rule = true;
                    }
                } else if (strcmp(expr_name, "cmp") == 0) {
                    uint32_t data_len;
                    const void *addr = nftnl_expr_get_data(expr, NFTNL_EXPR_CMP_DATA, &data_len);
                    if (addr && data_len == sizeof(ip_to_flush->s_addr) && memcmp(addr, &ip_to_flush->s_addr, sizeof(ip_to_flush->s_addr)) == 0) {
                        ip_is_involved = true;
                    }
                }
            }
            nftnl_expr_iter_destroy(iter);

            if (is_accept_rule && ip_is_involved) {
                nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "filter");
                nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "forward");

                struct nlmsghdr *del_nlh = nftnl_rule_nlmsg_build_hdr(
                    mnl_nlmsg_batch_current(del_batch),
                    NFT_MSG_DELRULE, NFPROTO_BRIDGE, NLM_F_ACK, del_seq++);
                nftnl_rule_nlmsg_build_payload(del_nlh, rule);
                mnl_nlmsg_batch_next(del_batch);
                delete_count++;
            }
            nftnl_rule_free(rule);
        }
    }
    if (ret < 0) {
        perror("mnl_socket_recvfrom in flush_nft_filter");
    }

    if (delete_count > 0) {
        nftnl_batch_end(mnl_nlmsg_batch_current(del_batch), del_seq++);
        mnl_nlmsg_batch_next(del_batch);

        Zf(mnl_socket_sendto(sock, mnl_nlmsg_batch_head(del_batch), mnl_nlmsg_batch_size(del_batch)) < 0,
           "kernel rejected filter flush batch");

        VERBOSE("flushed %d filter allow rule(s) involving guest %s",
                delete_count, inet_ntoa(*ip_to_flush));
    } else {
        VERBOSE("no filter allow rules found for guest %s to flush",
                inet_ntoa(*ip_to_flush));
    }

    mnl_nlmsg_batch_stop(del_batch);
    mnl_socket_close(sock);
}

/* Create a DNAT (Destination NAT) forward.

   This function will create a DNAT (Destination NAT) forward rule.

   1. Create the 'nat' table.
   2. Create a 'prerouting' or 'output' chain.
   3. Create a 'rule' to match the protocol and port.
   4. Create a 'rule' to match the guest IP and port.
   5. Create a 'rule' to perform the DNAT.
   6. Add the rule to the batch.
   7. Send the batch to the kernel.
   
   The assumption is that the forward rule doesn't already exist.
   If it does, this function will create a duplicate.
*/
void create_nft_forward(const struct in_addr *guest_ip, int host_port, int guest_port, const char *protocol) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "failed to bind socket");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    uint32_t seq = time(NULL);

    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);


    // Use the "nat" table.
    struct nftnl_table *table = nftnl_table_alloc();
    Tf(table != NULL, "failed to allocate 'table'");
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, "nat");

    struct nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWTABLE, NFPROTO_IPV4,
        NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    mnl_nlmsg_batch_next(batch);


    // Use the "prerouting" chain.
    struct nftnl_chain *chain = nftnl_chain_alloc();
    Tf(chain != NULL, "failed to allocate 'chain'");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, "nat");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, "prerouting");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "nat");
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_IP_PRE_ROUTING);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, -100); // DNAT priority

    nlh = nftnl_chain_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
        NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    nftnl_chain_free(chain);
    mnl_nlmsg_batch_next(batch);

    // Create a new rule.
    struct nftnl_rule *rule = nftnl_rule_alloc();
    Tf(rule != NULL, "failed to allocate 'rule'");
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "prerouting");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    
    // Match protocol.
    struct nftnl_expr *proto_expr = nftnl_expr_alloc("payload");
    Tf(proto_expr != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(proto_expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(proto_expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, protocol));
    nftnl_expr_set_u32(proto_expr, NFTNL_EXPR_PAYLOAD_LEN, 1);
    nftnl_expr_set_u32(proto_expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_3);
    nftnl_rule_add_expr(rule, proto_expr);

    struct nftnl_expr *cmp_proto_expr = nftnl_expr_alloc("cmp");
    Tf(cmp_proto_expr != NULL, "failed to allocate 'cmp' expression");
    int proto_num = (strcmp(protocol, "tcp") == 0) ? IPPROTO_TCP : IPPROTO_UDP;
    nftnl_expr_set_u32(cmp_proto_expr, NFTNL_EXPR_CMP_SREG, NFT_REG_3);
    nftnl_expr_set_u32(cmp_proto_expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_u8(cmp_proto_expr, NFTNL_EXPR_CMP_DATA, (uint8_t)proto_num);
    nftnl_rule_add_expr(rule, cmp_proto_expr);


    // Match host port.
    struct nftnl_expr *port_expr = nftnl_expr_alloc("payload");
    Tf(port_expr != NULL, "failed to allocate 'payload' expression");
    nftnl_expr_set_u32(port_expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    nftnl_expr_set_u32(port_expr, NFTNL_EXPR_PAYLOAD_OFFSET, 2);
    nftnl_expr_set_u32(port_expr, NFTNL_EXPR_PAYLOAD_LEN, 2);
    nftnl_expr_set_u32(port_expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_4);
    nftnl_rule_add_expr(rule, port_expr);

    struct nftnl_expr *cmp_port_expr = nftnl_expr_alloc("cmp");
    Tf(cmp_port_expr != NULL, "failed to allocate 'cmp' expression");
    nftnl_expr_set_u32(cmp_port_expr, NFTNL_EXPR_CMP_SREG, NFT_REG_4);
    nftnl_expr_set_u32(cmp_port_expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_u16(cmp_port_expr, NFTNL_EXPR_CMP_DATA, htons(host_port));
    nftnl_rule_add_expr(rule, cmp_port_expr);
    
    
    // Perform DNAT.
    struct nftnl_expr *imm_ip_expr = nftnl_expr_alloc("immediate");
    Tf(imm_ip_expr != NULL, "failed to allocate 'immediate' expression");
    nftnl_expr_set_u32(imm_ip_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_1);
    nftnl_expr_set_data(imm_ip_expr, NFTNL_EXPR_IMM_DATA, &guest_ip->s_addr, sizeof(guest_ip->s_addr));
    nftnl_rule_add_expr(rule, imm_ip_expr);
    
    struct nftnl_expr *imm_port_expr = nftnl_expr_alloc("immediate");
    Tf(imm_port_expr != NULL, "failed to allocate 'immediate' expression");
    nftnl_expr_set_u32(imm_port_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_2);
    uint16_t port_net = htons(guest_port);
    nftnl_expr_set_data(imm_port_expr, NFTNL_EXPR_IMM_DATA, &port_net, sizeof(port_net));
    nftnl_rule_add_expr(rule, imm_port_expr);

    struct nftnl_expr *dnat_expr = nftnl_expr_alloc("nat");
    Tf(dnat_expr != NULL, "failed to allocate 'nat' expression");
    nftnl_expr_set_u32(dnat_expr, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
    nftnl_expr_set_u32(dnat_expr, NFTNL_EXPR_NAT_REG_PROTO_MIN, NFT_REG_2);
    nftnl_expr_set_u32(dnat_expr, NFTNL_EXPR_NAT_TYPE, NFT_NAT_DNAT);
    nftnl_expr_set_u32(dnat_expr, NFTNL_EXPR_NAT_FAMILY, NFPROTO_IPV4);
    nftnl_rule_add_expr(rule, dnat_expr);
    

    // Add the rule to the batch.
    nlh = nftnl_rule_nlmsg_build_hdr(
        mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWRULE,
        nftnl_table_get_u32(table, NFTNL_TABLE_FAMILY),
        NLM_F_CREATE | NLM_F_ACK,
        seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule);
    mnl_nlmsg_batch_next(batch);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    // Send the batch to the kernel.
    if (mnl_socket_sendto(sock, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
      Zf(1, "kernel rejected port forwarding rule");
      mnl_socket_close(sock);
      return;
    }

    mnl_nlmsg_batch_stop(batch);
    nftnl_table_free(table);

    // Close the socket.
    VERBOSE("enabled port %s %d forwarding to container %s:%d",
            protocol, host_port, inet_ntoa(*guest_ip), guest_port);
    mnl_socket_close(sock);
}

/* Flush all forward rules for a given guest IP and protocol. */
void flush_nft_forward(const struct in_addr *guest_ip, const char *protocol) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "failed to bind socket");

    char get_buf[MNL_SOCKET_BUFFER_SIZE];
    char del_buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t get_seq = time(NULL);

    // 1. Build a GETRULE message to dump all rules from the chain.
    struct nlmsghdr *nlh_get = nftnl_nlmsg_build_hdr(
        get_buf, NFT_MSG_GETRULE, NFPROTO_IPV4, NLM_F_DUMP | NLM_F_ACK, get_seq);
    struct nftnl_rule *rule_template = nftnl_rule_alloc();
    Tf(rule_template != NULL, "failed to allocate rule template");
    nftnl_rule_set_str(rule_template, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule_template, NFTNL_RULE_CHAIN, "prerouting");
    nftnl_rule_nlmsg_build_payload(nlh_get, rule_template);
    nftnl_rule_free(rule_template);

    Zf(mnl_socket_sendto(sock, nlh_get, nlh_get->nlmsg_len) < 0, "failed to send GETRULE message");

    // 2. Prepare the delete batch.
    struct mnl_nlmsg_batch *del_batch = mnl_nlmsg_batch_start(del_buf, sizeof(del_buf));
    uint32_t del_seq = time(NULL);
    int delete_count = 0;
    int protocol_num = (strcmp(protocol, "tcp") == 0) ? IPPROTO_TCP : IPPROTO_UDP;

    nftnl_batch_begin(mnl_nlmsg_batch_current(del_batch), del_seq++);
    mnl_nlmsg_batch_next(del_batch);

    // 3. Receive rules and manually process them without a callback.
    int ret;
    char recv_buf[MNL_SOCKET_BUFFER_SIZE];
    bool done = false;

    while (!done && (ret = mnl_socket_recvfrom(sock, recv_buf, sizeof(recv_buf))) > 0) {
        struct nlmsghdr *nlh;
        int remaining_len = ret;

        for (nlh = (struct nlmsghdr *)recv_buf; mnl_nlmsg_ok(nlh, remaining_len); nlh = mnl_nlmsg_next(nlh, &remaining_len)) {
            // End of multipart message dump.
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            // Error from kernel.
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)mnl_nlmsg_get_payload(nlh);
                if (err->error != 0) {
                    fprintf(stderr, "Netlink error: %s\n", strerror(-err->error));
                }
                done = true;
                break;
            }

            // This is the core logic: parse the rule and check if it's a target.
            struct nftnl_rule *rule = nftnl_rule_alloc();
            Tf(rule != NULL, "failed to allocate rule");

            if (nftnl_rule_nlmsg_parse(nlh, rule) < 0) {
                perror("failed to parse rule message");
                nftnl_rule_free(rule);
                continue; // Skip to next message in buffer
            }

            bool proto_match = false;
            bool ip_match = false;
            bool dnat_match = false;

            struct nftnl_expr_iter *iter = nftnl_expr_iter_create(rule);
            struct nftnl_expr *expr;

            // Iterate over all expressions in the rule to find our matches.
            while ((expr = nftnl_expr_iter_next(iter)) != NULL) {
                const char *expr_name = nftnl_expr_get_str(expr, NFTNL_EXPR_NAME);
                if (!expr_name) continue;

                if (strcmp(expr_name, "cmp") == 0) {
                    if (nftnl_expr_get_u32(expr, NFTNL_EXPR_CMP_SREG) == NFT_REG_3 &&
                        nftnl_expr_get_u8(expr, NFTNL_EXPR_CMP_DATA) == protocol_num) {
                        proto_match = true;
                    }
                } else if (strcmp(expr_name, "immediate") == 0) {
                    if (nftnl_expr_get_u32(expr, NFTNL_EXPR_IMM_DREG) == NFT_REG_1) {
                        // The compiler indicates that nftnl_expr_get requires a third
                        // argument for data_len. We provide a variable for it here
                        // to fix the compilation error.
                        uint32_t data_len;
                        const void *addr = nftnl_expr_get(expr, NFTNL_EXPR_IMM_DATA, &data_len);
                        if (addr && data_len == sizeof(guest_ip->s_addr) && memcmp(addr, &guest_ip->s_addr, sizeof(guest_ip->s_addr)) == 0) {
                            ip_match = true;
                        }
                    }
                } else if (strcmp(expr_name, "nat") == 0) {
                    if (nftnl_expr_get_u32(expr, NFTNL_EXPR_NAT_TYPE) == NFT_NAT_DNAT &&
                        nftnl_expr_get_u32(expr, NFTNL_EXPR_NAT_REG_ADDR_MIN) == NFT_REG_1) {
                        dnat_match = true;
                    }
                }
            }
            nftnl_expr_iter_destroy(iter);

            // If all conditions are met, this is a rule we need to delete.
            if (proto_match && ip_match && dnat_match) {
                nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
                nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "prerouting");

                struct nlmsghdr *del_nlh = nftnl_rule_nlmsg_build_hdr(
                    mnl_nlmsg_batch_current(del_batch),
                    NFT_MSG_DELRULE,
                    NFPROTO_IPV4,
                    NLM_F_ACK,
                    del_seq++);
                nftnl_rule_nlmsg_build_payload(del_nlh, rule);
                mnl_nlmsg_batch_next(del_batch);
                delete_count++;
            }
            nftnl_rule_free(rule);
        }
    }
    if (ret < 0) {
        perror("mnl_socket_recvfrom");
    }

    // 4. If we found rules to delete, send the batch command.
    if (delete_count > 0) {
        nftnl_batch_end(mnl_nlmsg_batch_current(del_batch), del_seq++);
        mnl_nlmsg_batch_next(del_batch);

        Zf(mnl_socket_sendto(sock, mnl_nlmsg_batch_head(del_batch), mnl_nlmsg_batch_size(del_batch)) < 0,
           "kernel rejected delete batch");

        VERBOSE("flushed %d %s publish rule(s) for guest %s",
                delete_count, protocol, inet_ntoa(*guest_ip));
    } else {
        VERBOSE("no %s publish rules found for guest %s to flush",
                protocol, inet_ntoa(*guest_ip));
    }

    mnl_nlmsg_batch_stop(del_batch);
    mnl_socket_close(sock);
}

/* Create a VXLAN interface. 

   This function will create a VXLAN interface for the specified group and local IP addresses.

   1. Allocate a netlink socket.
   2. Allocate a vxlan link, set the name, type, VNI, group IP, local IP, and port.
   3. Send the vxlan link to the linux kernel.

   The assumption is that the vxlan link doesn't already exist with these parameters.
   If it does, this function will fail.
*/
void create_vxlan(const char *vxlan_name, uint32_t vni, const char *lower_device, const struct in_addr *group_ip, const struct in_addr *local_ip, uint16_t dstport) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket for VXLAN(create) with device");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket for VXLAN(create) with device");

    // Get the lower device.
    struct rtnl_link *lower_link;
    Zf(rtnl_link_get_kernel(sock, 0, lower_device, &lower_link) < 0, "failed to get lower device '%s'", lower_device);
    int lower_ifindex = rtnl_link_get_ifindex(lower_link);
    Zf(lower_ifindex <= 0, "invalid ifindex for lower device '%s'", lower_device);

    // Allocate a vxlan link.
    struct rtnl_link *vxlan_link = rtnl_link_vxlan_alloc();
    Tf(vxlan_link != NULL, "failed to allocate VXLAN link");

    // Set the name, VNI, and bind to lower device.
    rtnl_link_set_name(vxlan_link, vxlan_name);
    rtnl_link_vxlan_set_id(vxlan_link, vni);

    // Bind to lower device.
    rtnl_link_vxlan_set_link(vxlan_link, lower_ifindex);

    // Build addresses via nl_addr_parse to avoid byte-order/len pitfalls.
    char group_str[INET_ADDRSTRLEN], local_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &group_ip->s_addr, group_str, sizeof(group_str));
    inet_ntop(AF_INET, &local_ip->s_addr, local_str, sizeof(local_str));

    struct nl_addr *group_addr = NULL, *local_addr = NULL;
    Zf(nl_addr_parse(group_str, AF_INET, &group_addr) < 0, "failed to parse VXLAN group IP");
    Zf(nl_addr_parse(local_str, AF_INET, &local_addr) < 0, "failed to parse VXLAN local IP");

    // Set VXLAN attributes (group, local, port, ttl).
    Zf(rtnl_link_vxlan_set_group(vxlan_link, group_addr) < 0, "failed to set VXLAN group IP");
    Zf(rtnl_link_vxlan_set_local(vxlan_link, local_addr) < 0, "failed to set VXLAN local IP");
    rtnl_link_vxlan_set_port(vxlan_link, dstport);
    rtnl_link_vxlan_set_ttl(vxlan_link, 1);

    // Send to the kernel.
    Zf(rtnl_link_add(sock, vxlan_link, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK) < 0,
       "failed to create VXLAN interface '%s' (vni %u, dev %s)", vxlan_name, vni, lower_device);

    nl_addr_put(group_addr);
    nl_addr_put(local_addr);
    rtnl_link_put(vxlan_link);
    rtnl_link_put(lower_link);

    // Close the socket.
    VERBOSE("VXLAN interface '%s' created (vni %u, dev %s, group %s, local %s, dstport %u)",
            vxlan_name, vni, lower_device, inet_ntoa(*group_ip), inet_ntoa(*local_ip), dstport);
    nl_socket_free(sock);
}

/* Bring up a VXLAN interface. */
void set_vxlan_up(const char *vxlan_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket for VXLAN up");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket for VXLAN up");

    // Get the vxlan link
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, vxlan_name, &link) < 0, "failed to get VXLAN link '%s'", vxlan_name);

    // Clone the link so we can modify it.
    struct rtnl_link *link_change = rtnl_link_alloc();
    Zf(link_change == NULL, "failed to allocate link for VXLAN up");

    // Set the ifindex and flags (IFF_UP)
    rtnl_link_set_ifindex(link_change, rtnl_link_get_ifindex(link));
    rtnl_link_set_flags(link_change, IFF_UP);

    // Send the link change to the kernel.
    Zf(rtnl_link_change(sock, link, link_change, 0) < 0, "failed to bring up VXLAN '%s'", vxlan_name);

    rtnl_link_put(link_change);
    rtnl_link_put(link);

    VERBOSE("VXLAN '%s' brought up", vxlan_name);
    nl_socket_free(sock);
}

/* Check if a VXLAN interface exists with the specified remote IP and VNI.
   If vxlan_name is "*", it searches all VXLAN interfaces.
 */
bool is_vxlan_exists(uint32_t vni, const char *vxlan_name, const struct in_addr *remote_ip) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket for VXLAN check");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket for VXLAN check");

    bool found_match = false;

    if (strcmp(vxlan_name, "*") == 0) {
        // Iterate through all links to find a matching VXLAN interface
        struct nl_cache *cache;
        Zf(rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0, "failed to allocate link cache");

        struct rtnl_link *link_iter;
        for (link_iter = (struct rtnl_link *) nl_cache_get_first(cache);
             link_iter != NULL;
             link_iter = (struct rtnl_link *) nl_cache_get_next((struct nl_object *)link_iter)) {

            // Check if it's a VXLAN type
            if (rtnl_link_get_type(link_iter) == NULL || strcmp(rtnl_link_get_type(link_iter), "vxlan") != 0) {
                continue; // Not a VXLAN interface, skip
            }

            struct nl_addr *group_addr = NULL;
            struct in_addr group_ip_found = {0};
            bool remote_ip_matches_current = false;
            uint32_t vni_found = 0;

            int err_get_group = rtnl_link_vxlan_get_group(link_iter, &group_addr);
            int err_get_id = rtnl_link_vxlan_get_id(link_iter, &vni_found);

            if (err_get_group == 0 && group_addr != NULL && nl_addr_get_family(group_addr) == AF_INET) {
                memcpy(&group_ip_found, nl_addr_get_binary_addr(group_addr), sizeof(group_ip_found));
                if (group_ip_found.s_addr == remote_ip->s_addr) {
                    remote_ip_matches_current = true;
                }
            }

            if (remote_ip_matches_current && (err_get_id == 0 && vni_found == vni)) {
                found_match = true;
                char expected_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, remote_ip, expected_ip_str, sizeof(expected_ip_str));
                VERBOSE("VXLAN interface '%s' with remote IP '%s' and VNI %u found (wildcard search)",
                        rtnl_link_get_name(link_iter), expected_ip_str, vni);
                if (group_addr) {
                    nl_addr_put(group_addr);
                }
                break; // Found a match, no need to continue iterating
            } else {
                char expected_ip_str[INET_ADDRSTRLEN];
                char found_ip_str[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, remote_ip, expected_ip_str, sizeof(expected_ip_str));
                if (err_get_group == 0 && group_addr != NULL && nl_addr_get_family(group_addr) == AF_INET) {
                    inet_ntop(AF_INET, &group_ip_found, found_ip_str, sizeof(found_ip_str));
                } else {
                    snprintf(found_ip_str, sizeof(found_ip_str), "N/A");
                }
                VERBOSE("Considering VXLAN interface '%s' but remote IP or VNI mismatch. Expected IP: %s, VNI: %u. Found IP: %s, VNI: %u",
                        rtnl_link_get_name(link_iter), expected_ip_str, vni,
                        found_ip_str, (err_get_id == 0) ? vni_found : 0);
            }

            if (group_addr) {
                nl_addr_put(group_addr);
            }
        }
        nl_cache_free(cache);

    } else {
        // Original logic: check for a specific VXLAN interface by name
        struct rtnl_link *link;
        if (rtnl_link_get_kernel(sock, 0, vxlan_name, &link) < 0) {
            VERBOSE("VXLAN interface '%s' not found", vxlan_name);
            nl_socket_free(sock);
            return false;
        }

        // Check if it's actually a VXLAN type.
        if (strcmp(rtnl_link_get_type(link), "vxlan") != 0) {
            VERBOSE("Interface '%s' found but is not of type VXLAN", vxlan_name);
            rtnl_link_put(link);
            nl_socket_free(sock);
            return false;
        }

        // Check remote IP (group) and VNI.
        struct nl_addr *group_addr = NULL;
        struct in_addr group_ip_found = {0};
        bool remote_ip_matches = false;
        uint32_t vni_found = 0;

        int err_get_group = rtnl_link_vxlan_get_group(link, &group_addr);
        int err_get_id = rtnl_link_vxlan_get_id(link, &vni_found);

        if (err_get_group == 0 && group_addr != NULL && nl_addr_get_family(group_addr) == AF_INET) {
            memcpy(&group_ip_found, nl_addr_get_binary_addr(group_addr), sizeof(group_ip_found));
            if (group_ip_found.s_addr == remote_ip->s_addr) {
                remote_ip_matches = true;
            }
        }

        found_match = remote_ip_matches && (err_get_id == 0 && vni_found == vni);

        char expected_ip_str[INET_ADDRSTRLEN];
        char found_ip_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, remote_ip, expected_ip_str, sizeof(expected_ip_str));
        if (err_get_group == 0 && group_addr != NULL && nl_addr_get_family(group_addr) == AF_INET) {
            inet_ntop(AF_INET, &group_ip_found, found_ip_str, sizeof(found_ip_str));
        } else {
            snprintf(found_ip_str, sizeof(found_ip_str), "N/A");
        }

        if (found_match) {
            VERBOSE("VXLAN interface '%s' with remote IP '%s' and VNI %u found",
                    vxlan_name, expected_ip_str, vni);
        } else {
            VERBOSE("VXLAN interface '%s' found but remote IP or VNI mismatch. Expected IP: %s, VNI: %u. Found IP: %s, VNI: %u",
                    vxlan_name, expected_ip_str, vni,
                    found_ip_str, (err_get_id == 0) ? vni_found : 0);
        }

        // Clean up
        if (group_addr) {
            nl_addr_put(group_addr);
        }
        rtnl_link_put(link);
    }

    nl_socket_free(sock);
    return found_match;
}

/* Set the VXLAN interface to the specified bridge */
void set_vxlan_bridge(const char *vxlan_name, const char *bridge_name) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket for VXLAN bridge attachment");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket for VXLAN bridge attachment");

    // Get the VXLAN and bridge links.
    struct rtnl_link *vxlan_link, *bridge_link;
    Zf(rtnl_link_get_kernel(sock, 0, vxlan_name, &vxlan_link) < 0, "failed to get VXLAN link '%s'", vxlan_name);
    Zf(rtnl_link_get_kernel(sock, 0, bridge_name, &bridge_link) < 0, "failed to get bridge link '%s'", bridge_name);

    // Clone the VXLAN link so we can modify it.
    struct rtnl_link *link_change = rtnl_link_alloc();
    Zf(link_change == NULL, "failed to allocate link for VXLAN bridge attachment");

    // Set the ifindex and master (bridge's ifindex).
    rtnl_link_set_ifindex(link_change, rtnl_link_get_ifindex(vxlan_link));
    rtnl_link_set_master(link_change, rtnl_link_get_ifindex(bridge_link));

    // Send the link change to the kernel.
    Zf(rtnl_link_change(sock, vxlan_link, link_change, 0) < 0,
       "failed to attach VXLAN '%s' to bridge '%s'", vxlan_name, bridge_name);

    rtnl_link_put(link_change);
    rtnl_link_put(vxlan_link);
    rtnl_link_put(bridge_link);

    VERBOSE("VXLAN interface '%s' attached to bridge '%s'", vxlan_name, bridge_name);
    nl_socket_free(sock);
}

/* Get IPv4 address and interface name used by the default route. */
bool get_default_ipv4(struct in_addr *out_ip, char *out_ifname, size_t ifname_len) {
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) return false;
    if (nl_connect(sock, NETLINK_ROUTE) < 0) { nl_socket_free(sock); return false; }

    // Get the route cache.
    struct nl_cache *route_cache = NULL;
    if (rtnl_route_alloc_cache(sock, AF_INET, 0, &route_cache) < 0) {
        nl_socket_free(sock);
        return false;
    }

    // To derive output ifindex from a route's nexthops.
    int route_get_oif_compat(struct rtnl_route *route) {
        int num_nexthops = rtnl_route_get_nnexthops(route);
        for (int i = 0; i < num_nexthops; i++) {
            struct rtnl_nexthop *nh = rtnl_route_nexthop_n(route, i);
            if (!nh) continue;
            int ifindex = rtnl_route_nh_get_ifindex(nh);
            if (ifindex > 0) return ifindex;
        }
        return 0;
    }

    struct rtnl_route *best_route = NULL;
    uint32_t best_priority = UINT32_MAX;

    // Find the best route through the route cache.
    for (struct rtnl_route *rt = (struct rtnl_route *) nl_cache_get_first(route_cache);
         rt != NULL;
         rt = (struct rtnl_route *) nl_cache_get_next((struct nl_object *) rt)) {

        // Get the destination address and prefix length.
        struct nl_addr *dst = rtnl_route_get_dst(rt);
        int prefixlen = dst ? nl_addr_get_prefixlen(dst) : 0;
        if (dst && nl_addr_get_family(dst) != AF_INET) continue;

        // Default route if no dst or /0.
        if (dst == NULL || prefixlen == 0) {
            int oif = route_get_oif_compat(rt);
            if (oif <= 0) continue; // Require explicit output interface.

            uint32_t prio = rtnl_route_get_priority(rt);
            if (best_route == NULL || prio < best_priority) {
                best_route = rt;
                best_priority = prio;
            }
        }
    }

    // No best route found.
    if (best_route == NULL) {
        nl_cache_free(route_cache);
        nl_socket_free(sock);
        return false;
    }

    // Get the output interface index.
    int ifindex = route_get_oif_compat(best_route);
    if (ifindex <= 0) {
        nl_cache_free(route_cache);
        nl_socket_free(sock);
        return false;
    }

    // Resolve interface name.
    struct nl_cache *link_cache = NULL;
    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache) < 0) {
        nl_cache_free(route_cache);
        nl_socket_free(sock);
        return false;
    }

    // Get the link.
    struct rtnl_link *link = rtnl_link_get(link_cache, ifindex);
    if (link && out_ifname && ifname_len > 0) {
        const char *name = rtnl_link_get_name(link);
        if (name) {
            strncpy(out_ifname, name, ifname_len - 1);
            out_ifname[ifname_len - 1] = '\0';
        }
    }

    // Find an IPv4 address on this interface.
    bool found_ip = false;
    struct nl_cache *addr_cache = NULL;
    if (rtnl_addr_alloc_cache(sock, &addr_cache) == 0) {
        for (struct rtnl_addr *a = (struct rtnl_addr *) nl_cache_get_first(addr_cache);
             a != NULL;
             a = (struct rtnl_addr *) nl_cache_get_next((struct nl_object *) a)) {
            if (rtnl_addr_get_ifindex(a) != ifindex) continue;
            struct nl_addr *local = rtnl_addr_get_local(a);
            if (!local || nl_addr_get_family(local) != AF_INET) continue;
            if (out_ip) {
                memcpy(out_ip, nl_addr_get_binary_addr(local), sizeof(struct in_addr));
                found_ip = true;
                break;
            }
        }
    }

    // Free the caches and the socket.
    if (addr_cache) nl_cache_free(addr_cache);
    if (link) rtnl_link_put(link);
    if (link_cache) nl_cache_free(link_cache);
    if (route_cache) nl_cache_free(route_cache);
    nl_socket_free(sock);
    return found_ip;
}