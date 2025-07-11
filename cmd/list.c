#define _GNU_SOURCE
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

#define CONTAINERS_DIR "/var/lib/clearly/containers"

int main(int argc, char *argv[]) {
    DIR *d;
    struct dirent *dir;
    bool json_output = (argc == 2 && strcmp(argv[1], "--json") == 0);

    d = opendir(CONTAINERS_DIR);
    if (!d) {
        if (errno == ENOENT) {
            if (json_output) {
                printf("[]\n");
            } else {
                printf("CONTAINER ID\tSTATUS\n");
            }
            return 0;
        }
        perror("opendir");
        return 1;
    }

    if (json_output) {
        printf("[\n");
    } else {
        printf("%-20s\t%s\n", "CONTAINER ID", "STATUS");
    }

    bool first_item = true;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
            char *container_name = dir->d_name;
            char pid_path[PATH_MAX];
            
            int ret = snprintf(pid_path, sizeof(pid_path), "%s/%s/pid", CONTAINERS_DIR, container_name);
            if (ret >= sizeof(pid_path) || ret < 0) {
                fprintf(stderr, "Error: path too long for container %s\n", container_name);
                continue;
            }

            FILE *f = fopen(pid_path, "r");
            if (!f) {
                continue;
            }

            pid_t pid;
            if (fscanf(f, "%d", &pid) == 1) {
                const char *status_str;
                if (kill(pid, 0) == 0) {
                    status_str = "Running";
                } else if (errno == ESRCH) {
                    status_str = "Stopped";
                } else {
                    status_str = "Unknown";
                }

                if (json_output) {
                    if (!first_item) {
                        printf(",\n");
                    }
                    printf("  {\"id\": \"%s\", \"status\": \"%s\"}", container_name, status_str);
                    first_item = false;
                } else {
                    printf("%-20s\t%s\n", container_name, status_str);
                }
            }
            fclose(f);
        }
    }

    if (json_output) {
        printf("\n]\n");
    }

    closedir(d);
    return 0;
}