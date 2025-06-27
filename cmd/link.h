/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>

/** Function prototypes **/

/* Bridge */
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

/* SNAT (Source NAT) */
void create_snat_masquerade(const struct in_addr *subnet, int cidr);
bool is_snat_masquerade_exists(const struct in_addr *subnet);

/* DNAT (Destination NAT) */
void create_dnat_forwarding(int host_port, int guest_port, const struct in_addr *guest_ip);
bool is_dnat_forwarding_exists(int host_port, const struct in_addr *guest_ip, int guest_port);
void delete_dnat_forwarding(int host_port, const struct in_addr *guest_ip, int guest_port);
