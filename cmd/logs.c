/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

#define CONTAINERS_DIR "/var/lib/clearly/containers"

void print_logs(FILE *f, bool follow) {
    char buffer[4096];
    
    // Print existing content
    while (fgets(buffer, sizeof(buffer), f) != NULL) {
        printf("%s", buffer);
    }

    if (!follow) {
        return;
    }

    // Follow for new content
    while (true) {
        clearerr(f);
        // We could seek to the end before the loop, but if the file was rotated,
        // this is safer. For simple appending, ftell/fseek is fine.
        while (fgets(buffer, sizeof(buffer), f) != NULL) {
            printf("%s", buffer);
        }
        fflush(stdout);
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: clearly logs [-f|--follow] <container_id>\n");
        return 1;
    }

    bool follow = false;
    char *container_name = NULL;

    if (argc == 2) {
        container_name = argv[1];
    } else if (argc == 3) {
        if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--follow") == 0) {
            follow = true;
            container_name = argv[2];
        } else if (strcmp(argv[2], "-f") == 0 || strcmp(argv[2], "--follow") == 0) {
            follow = true;
            container_name = argv[1];
        } else {
            fprintf(stderr, "Usage: clearly logs [-f|--follow] <container_id>\n");
            return 1;
        }
    }

    if (container_name == NULL) {
        fprintf(stderr, "Usage: clearly logs [-f|--follow] <container_id>\n");
        return 1;
    }

    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/%s/log", CONTAINERS_DIR, container_name);

    FILE *f = fopen(log_path, "r");
    if (!f) {
        fprintf(stderr, "Error: container '%s' not found or no logs available.\n", container_name);
        return 1;
    }

    print_logs(f, follow);

    fclose(f);
    return 0;
} 