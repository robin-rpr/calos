/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/** Function prototypes **/

/* Basic */
bool is_link_exists(const char *link_name);

/* Bridge (Layer 2 switch) */
void create_bridge(const char *bridge_name, const struct in_addr *ip, int cidr);
bool is_bridge_exists(const char *bridge_name);

/* Veth (Virtual Ethernet) */
void create_veth_pair(const char *host_name, const char *peer_name);
void set_veth_bridge(const char *veth_name, const char *bridge_name);
void set_veth_up(const char *veth_name);
void set_veth_name(const char *veth_name, const char *new_name);
void set_veth_route(const char *veth_name, const struct in_addr *gateway, const char *destination);
void set_veth_ip(const char *veth_name, const struct in_addr *ip, int cidr);
void set_veth_ns_pid(const char *link_name, pid_t pid);
void set_veth_mac(const char *veth_name);

/* NFT (Netfilter Table) Masquerade */
void create_nft_masquerade(const struct in_addr *subnet, int cidr);
bool is_nft_masquerade_exists(const struct in_addr *subnet);

/* NFT (Netfilter Table) Filter */
void create_nft_filter(const struct in_addr *subnet, int cidr);
bool is_nft_filter_exists(const struct in_addr *subnet);
void set_nft_filter_allow(const struct in_addr *src_ip, const struct in_addr *dst_ip);
void flush_nft_filter(const struct in_addr *ip_to_flush);

/* NFT (Netfilter Table) Forward */
void create_nft_forward(const struct in_addr *guest_ip, int host_port, int container_port, const char *protocol);
void flush_nft_forward(const struct in_addr *guest_ip, const char *protocol);

/* VXLAN (Virtual Extensible LAN) */
void create_vxlan(const char *vxlan_name, uint32_t vni, const struct in_addr *remote_ip);
bool is_vxlan_exists(uint32_t vni, const char *vxlan_name, const struct in_addr *remote_ip);
void set_vxlan_bridge(const char *vxlan_name, const char *bridge_name);