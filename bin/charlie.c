#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LIBEXECDIR
#  define LIBEXECDIR "/usr/local/libexec/charlie"
#endif

int main(int argc, char *argv[])
{
	char *exec_path, *subcommand;
	char **new_argv;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s SUBCOMMAND [ARG...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	subcommand = argv[1];
	if (asprintf(&exec_path, "%s/ch-%s", LIBEXECDIR, subcommand) < 0) {
		perror("asprintf");
		exit(EXIT_FAILURE);
	}

	new_argv = &argv[1];
	new_argv[0] = exec_path;

	execv(exec_path, new_argv);

	perror("execv");
	exit(EXIT_FAILURE);
} 