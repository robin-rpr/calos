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
	char *exec_path, *subcommand;
	char **new_argv;

	/* Check if the subcommand is provided. */
	if (argc < 2) {
		fprintf(stderr, "Usage: %s SUBCOMMAND [ARG...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Ensure the network bridge exists. */
	if (!is_bridge_exists("clearly0")) {
		srand((unsigned int)getpid() ^ (unsigned int)time(NULL));
		uint32_t ip = (10 << 24) | ((rand() & 0xFF) << 16) | ((rand() & 0xFF) << 8) | (rand() & 0xFF);
		struct in_addr bridge_ip = { .s_addr = htonl(ip) }; // 10.x.x.x
		create_bridge("clearly0", &bridge_ip, 8);
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