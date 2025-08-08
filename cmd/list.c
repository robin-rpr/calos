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

#include "misc.h"


/** Function prototypes (private) **/

char *runtime_default(void);


/** Functions **/

/* Return path to the runtime directory. */
char *runtime_default(void)
{
   char *runtime = getenv("CLEARLY_RUNTIME_STORAGE");

   if (runtime == NULL)
      T_ (1 <= asprintf(&runtime, "/run/clearly"));

   return runtime;
}


/** Main **/

int main(int argc, char *argv[]) {
    DIR *d;
    struct dirent *dir;
    bool json_output = (argc == 2 && strcmp(argv[1], "--json") == 0);

    username_set();
    char *runtime = runtime_default();

    d = opendir(runtime);
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
        printf("%-20s\t%-15s\t%s\n", "CONTAINER ID", "IP ADDRESS", "STATUS");
    }

    bool first_item = true;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
            char path[PATH_MAX];
            char pid_path[PATH_MAX];
            char net_path[PATH_MAX];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
            snprintf(path, sizeof(path), "%s/%s", runtime, dir->d_name);
            snprintf(pid_path, sizeof(pid_path), "%s/pid", path);
            snprintf(net_path, sizeof(net_path), "%s/net", path);
#pragma GCC diagnostic pop

            FILE *f = fopen(pid_path, "r");
            if (!f) {
                continue;
            }

            char ip_addr[16] = "N/A";
            FILE *net_f = fopen(net_path, "r");
            if (net_f) {
                if (fgets(ip_addr, sizeof(ip_addr), net_f) != NULL) {
                    ip_addr[strcspn(ip_addr, "\n")] = '\0';
                }
                fclose(net_f);
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
                    printf("  {\"id\": \"%s\", \"ip_address\": \"%s\", \"status\": \"%s\"}", dir->d_name, ip_addr, status_str);
                    first_item = false;
                } else {
                    printf("%-20s\t%-15s\t%s\n", dir->d_name, ip_addr, status_str);
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