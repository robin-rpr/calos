/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include <linux/netfilter/nf_tables.h>
#include <linux/if_bridge.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
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
#include <libnl3/netlink/route/link/bridge.h>

#include "misc.h"
#include "link.h"


/** Macros **/

/* Linux Kernel constants for netfilter.
   partially sourced from <linux/netfilter/nf_tables.h> */
#define NFPROTO_IPV4 2

#define NF_ACCEPT 1
#define NF_INET_POST_ROUTING 4

#define NFT_PRIORITY_NAT_POSTROUTING -100
#define NFT_POLICY_ACCEPT 0

#define NFTNL_EXPR_META_LEN 3
#define NFTNL_EXPR_META_DEV 4

#ifndef __KERNEL__
/* IP Cache bits. */
/* Src IP address. */
#define NFC_IP_SRC		0x0001
/* Dest IP address. */
#define NFC_IP_DST		0x0002
/* Input device. */
#define NFC_IP_IF_IN		0x0004
/* Output device. */
#define NFC_IP_IF_OUT		0x0008
/* TOS. */
#define NFC_IP_TOS		0x0010
/* Protocol. */
#define NFC_IP_PROTO		0x0020
/* IP options. */
#define NFC_IP_OPTIONS		0x0040
/* Frag & flags. */
#define NFC_IP_FRAG		0x0080

/* Per-protocol information: only matters if proto match. */
/* TCP flags. */
#define NFC_IP_TCPFLAGS		0x0100
/* Source port. */
#define NFC_IP_SRC_PT		0x0200
/* Dest port. */
#define NFC_IP_DST_PT		0x0400
/* Something else about the proto */
#define NFC_IP_PROTO_UNKNOWN	0x2000

/* IP Hooks */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5
#endif /* ! __KERNEL__ */

#ifndef IFLA_BRIDGE_VLAN_INFO
#define IFLA_BRIDGE_VLAN_INFO 2
#endif

#ifndef BRIDGE_VLAN_INFO_PVID
#define BRIDGE_VLAN_INFO_PVID (1 << 1)
#endif

#ifndef BRIDGE_VLAN_INFO_UNTAGGED
#define BRIDGE_VLAN_INFO_UNTAGGED (1 << 2)
#endif

/** Functions **/

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

    // Configure the IP Address & CIDR.
    // Allocate an address, set the local IP address, and set the ifindex.
    struct rtnl_addr *addr = rtnl_addr_alloc();
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

/* Enable VLAN filtering on a bridge. */
void set_bridge_vlan_enabled(const char *bridge_name, uint16_t start, uint16_t end, int untagged) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link.
    struct rtnl_link *bridge;
    Zf(rtnl_link_get_kernel(sock, 0, bridge_name, &bridge) < 0, "failed to get bridge link '%s'", bridge_name);

    // Enable VLAN filtering on the bridge port.
    Zf(rtnl_link_bridge_enable_vlan(bridge) < 0, "failed to enable VLAN on bridge '%s'", bridge_name);

    // Set the VLAN membership range.
    Zf(rtnl_link_bridge_set_port_vlan_map_range(bridge, start, end, untagged) < 0,
       "failed to set bridge '%s' VLAN membership range to '%d' until '%d' (untagged: %d)",
       bridge_name, start, end, untagged);
    rtnl_link_put(bridge);

    // Free the socket.
    VERBOSE("bridge '%s' set VLAN membership range to '%d' until '%d' (untagged: %d)",
            bridge_name, start, end, untagged);
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
   
   rtnl_link_set_flags(link_change, IFF_UP); // TODO

   // Send the link change to the kernel.
   Zf(rtnl_link_change(sock, link, link_change, 0) < 0, "failed to attach '%s' to bridge '%s'", veth_name, bridge_name);
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
    rtnl_route_nh_set_ifindex(nexthop, rtnl_link_get_ifindex(link));
    rtnl_route_nh_set_gateway(nexthop, gateway_addr);
    rtnl_route_add_nexthop(route_change, nexthop);
    nl_addr_put(gateway_addr);

    // Send the route change to the kernel.
    Zf(rtnl_route_add(sock, route_change, 0) < 0, "failed to add default route to '%s'", veth_name);
    rtnl_route_put(route_change);

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

    // Free the socket.
    VERBOSE("veth '%s' IP address set to '%s'", veth_name, ip_str);
    nl_socket_free(sock);
}

/* Set a veth to a given VLAN. */
void set_veth_vlan(const char *veth_name, int vlan) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Get the veth link.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, veth_name, &link) < 0, "failed to get link '%s'", veth_name);

    // Clone the link so we can modify it.
    struct rtnl_link *link_change = rtnl_link_alloc();
    Zf(link_change == NULL, "failed to allocate link");

    // Allocate a netlink message.
    struct nl_msg *simple_msg = nlmsg_alloc_simple(RTM_SETLINK, NLM_F_REQUEST);
    Tf(simple_msg != NULL, "failed to allocate simple netlink message");

    // Get the ifindex of the veth.
    int if_index = rtnl_link_get_ifindex(link);
    Zf(if_index <= 0, "invalid ifindex for link '%s'", veth_name);

    // Allocate a netlink message for the ifindex.
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index = if_index,
    };
    nlmsg_append(simple_msg, &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO);

    struct nlattr *af_spec = nla_nest_start(simple_msg, IFLA_AF_SPEC);
    struct nlattr *af_bridge_vlan = nla_nest_start(simple_msg, IFLA_BRIDGE_VLAN_INFO);

    struct bridge_vlan_info vlan_info = {
        .flags = BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED,
        .vid = 100,
    };
    nla_put(simple_msg, IFLA_BRIDGE_VLAN_INFO, sizeof(vlan_info), &vlan_info);

    // Finish the IFLA_BRIDGE_VLAN_INFO nesting
    nla_nest_end(simple_msg, af_bridge_vlan);
    nla_nest_end(simple_msg, af_spec);

    // Send the message to the kernel.
    Zf(nl_send_auto_complete(sock, simple_msg) < 0, "failed to send netlink message");
    Zf(nl_wait_for_ack(sock) < 0, "failed to wait for netlink ack");
    rtnl_link_put(link);
    nlmsg_free(simple_msg);

    // Free the socket.
    VERBOSE("veth '%s' set to VLAN %d", veth_name, vlan);
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
void create_snat_masquerade(const struct in_addr *subnet, int cidr) {
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
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "postrouting");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    // Create a match 'expr'ession for the subnet.
    struct nftnl_expr *match;
    match = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
    nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, match);

    // Create a 'bitwise' allocation for the CIDR.
    uint32_t mask = htonl(0xFFFFFFFF << (32 - cidr));
    match = nftnl_expr_alloc("bitwise");
    nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
    nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
    nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_LEN, sizeof(uint32_t));
    nftnl_expr_set_data(match, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
    uint32_t zero = 0;
    nftnl_expr_set_data(match, NFTNL_EXPR_BITWISE_XOR, &zero, sizeof(zero));
    nftnl_rule_add_expr(rule, match);

    // Create a comparison 'expr'ession for the subnet.
    match = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(match, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(match, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(match, NFTNL_EXPR_CMP_DATA, &subnet, sizeof(subnet));
    nftnl_rule_add_expr(rule, match);

    // Create the 'masq' expression.
    struct nftnl_expr *expr = nftnl_expr_alloc("masq");
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
bool is_snat_masquerade_exists(const struct in_addr *subnet) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
    Tf(sock != NULL, "Failed to open netlink socket for masquerade");
    Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for masquerade");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);

    // Request dump of all rules
    struct nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_IPV4, NLM_F_DUMP, seq);

    struct nftnl_rule *req = nftnl_rule_alloc();
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
                    uint32_t len = 0;
                     const void *data = nftnl_expr_get_data(expr, NFTNL_EXPR_CMP_DATA, &len);
                     if (data && len == sizeof(uint32_t)) {
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
                    return true;
                }
            }
        }

        if (len == 0) return false;
    }

    mnl_socket_close(sock);
    return false;
}

/* Create a DNAT forwarding rule.

   This function will create a DNAT forwarding rule for the specified host port
   to the specified guest IP and port.

   1. Create the 'nat' table.
   2. Create the 'prerouting' chain.
   3. Create a match 'expr'ession for the protocol.
   4. Create a match 'expr'ession for the destination port.
   5. Create a DNAT 'expr'ession.
   6. Send the rule to the kernel.

   The assumption is that the DNAT rule doesn't already exist and
   that a SNAT masquerade rule exists for the specified subnet.
   If this is not the case, this function will fail.
*/
void create_dnat_forwarding(int host_port, int guest_port, const struct in_addr *guest_ip) {
    struct mnl_socket *sock = mnl_socket_open(NETLINK_NETFILTER);
      Tf(sock != NULL, "Failed to open netlink socket for port forwarding");
      Zf(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for port forwarding");

      char buf[MNL_SOCKET_BUFFER_SIZE * 2];
      uint32_t seq = time(NULL);
      struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

      nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
      mnl_nlmsg_batch_next(batch);

    struct nftnl_rule *rule = nftnl_rule_alloc();
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "prerouting");

    // Match TCP protocol
    struct nftnl_expr *expr = nftnl_expr_alloc("meta");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_L4PROTO);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    uint8_t proto = IPPROTO_TCP;
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &proto, sizeof(proto));
    nftnl_rule_add_expr(rule, expr);

    // Match destination port
    expr = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct tcphdr, dest));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint16_t));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    uint16_t hport = htons(host_port);
    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &hport, sizeof(hport));
    nftnl_rule_add_expr(rule, expr);

    // Set DNAT to guest_ip:guest_port
    expr = nftnl_expr_alloc("nat");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_TYPE, NFT_NAT_DNAT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_FAMILY, NFPROTO_IPV4);
    nftnl_expr_set_data(expr, NFTNL_EXPR_NAT_REG_ADDR_MIN, &guest_ip->s_addr, sizeof(uint32_t));
    uint16_t gport = htons(guest_port);
    nftnl_expr_set_data(expr, NFTNL_EXPR_NAT_REG_PROTO_MIN, &gport, sizeof(uint16_t));
    nftnl_rule_add_expr(rule, expr);

    struct nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWRULE, NFPROTO_IPV4, NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule);

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    Zf(mnl_socket_sendto(sock, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0,
   "kernel rejected port forwarding rule");

    mnl_socket_close(sock);
    VERBOSE("nftables DNAT rule added for tcp host port %d -> %s:%d", host_port, inet_ntoa(*guest_ip), guest_port);
}

bool is_dnat_forwarding_exists(int host_port, const struct in_addr *guest_ip, int guest_port) {
    // ...
    return false;
}

void delete_dnat_forwarding(int host_port, const struct in_addr *guest_ip, int guest_port) {
    // ...
}