#define _GNU_SOURCE
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef CMDDIR
#  define CMDDIR "/usr/local/libexec"
#endif

int main(int argc, char *argv[])
{
	struct passwd *clearly_user;
	char *exec_path, *subcommand;
	char **new_argv;
	

	if (argc < 2) {
		fprintf(stderr, "Usage: %s SUBCOMMAND [ARG...]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Attempt to switch to 'clearly' user for security */
	clearly_user = getpwnam("clearly");
	if (clearly_user == NULL || setuid(clearly_user->pw_uid) != 0) {
		fprintf(stderr, "WARNING: Clearly was unable to drop privileges. Please consider using a normal user account.\n");
	}

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