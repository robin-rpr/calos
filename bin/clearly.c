#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "misc.h"
#include "net.h"

#ifndef CMDDIR
#  define CMDDIR "/usr/local/libexec"
#endif

int main(int argc, char *argv[])
{
	char *exec_path, *subcommand;
	char **new_argv;

	/* Check if the subcommand is provided. */
	if (argc < 2) {
		fprintf(stderr, "Usage: %s SUBCOMMAND [ARG...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Handle --version flag */
	if (strcmp(argv[1], "--version") == 0) {
		subcommand = "version";
	} else {
		subcommand = argv[1];
	}

	/* Ensure the network bridge exists. */
	if (!is_bridge_exists("clearly0")) {
		char *subnet = config_get("Subnet");
		int cidr = 0; char ip_str[16];
		struct in_addr subnet_ip = { .s_addr = 0 };
		sscanf(subnet, "%15[^/]/%d", ip_str, &cidr);
		inet_pton(AF_INET, ip_str, &subnet_ip);
		srand((unsigned int)getpid() ^ (unsigned int)time(NULL));
		uint32_t subnet_base = ntohl(subnet_ip.s_addr);
		uint32_t host_bits = 32 - cidr;
		uint32_t host_mask = (1U << host_bits) - 1;
		uint32_t network_mask = ~host_mask;
		uint32_t random_host = rand() & host_mask;
		uint32_t ip = (subnet_base & network_mask) | random_host;
		struct in_addr bridge_ip = { .s_addr = htonl(ip) };
		create_bridge("clearly0", &bridge_ip, cidr);
	}

	/* Ensure the vxlan link exists. */
	if (!is_vxlan_exists("vxclearly0")) {
		struct in_addr group_ip = { .s_addr = inet_addr("239.0.0.1") };
		struct in_addr local_ip;
		char ifname[IFNAMSIZ];
		get_default_interface(ifname, sizeof(ifname));
		get_interface_ipv4(ifname, &local_ip);
		create_vxlan("vxclearly0", 4242, ifname, &group_ip, &local_ip, 4789);
		set_vxlan_bridge("vxclearly0", "clearly0");
		set_vxlan_up("vxclearly0");
	}

	/* Execute the subcommand. */
	if (asprintf(&exec_path, "%s/%s", CMDDIR, subcommand) < 0) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}

	new_argv = &argv[1];
	new_argv[0] = exec_path;

	execv(exec_path, new_argv);

	perror("execv");
	exit(EXIT_FAILURE);
} 