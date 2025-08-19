#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "misc.h"
#include "net.h"

#ifndef CMDDIR
#  define CMDDIR "/usr/local/libexec"
#endif

int main(int argc, char *argv[])
{
	struct in_addr bridge_ip = { .s_addr = inet_addr("10.0.0.1") };
	struct in_addr group_ip = { .s_addr = inet_addr("239.0.0.1") };
	char *exec_path, *subcommand;
	char **new_argv;

	/* Check if the subcommand is provided. */
	if (argc < 2) {
		fprintf(stderr, "Usage: %s SUBCOMMAND [ARG...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Ensure the network bridge exists. */
	if (!is_bridge_exists("clearly0")) {
		create_bridge("clearly0", &bridge_ip, 8);
	}

	/* Ensure the vxlan link exists. */
	if (!is_vxlan_exists(4242, "vxclearly0", &group_ip)) {
		struct in_addr local_ip;
		char ifname[IFNAMSIZ];
		get_default_ipv4(&local_ip, ifname, sizeof(ifname));
		create_vxlan("vxclearly0", 4242, ifname, &group_ip, &local_ip, 4789);
		set_vxlan_bridge("vxclearly0", "clearly0");
		set_vxlan_up("vxclearly0");
	}

	/* Execute the subcommand. */
	subcommand = argv[1];
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