/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#define CONTAINERS_DIR "/var/lib/clearly/containers"

// Helper function to remove a directory and its contents
int remove_directory(const char *path) {
    char pid_path[PATH_MAX];
    char log_path[PATH_MAX];

    if (snprintf(pid_path, sizeof(pid_path),
                "%s/pid", path) >= sizeof(pid_path) ||
        snprintf(log_path, sizeof(log_path),
                "%s/log", path) >= sizeof(log_path)) {
        fprintf(stderr, "Path too long.\n");
        return -1;
    }

    remove(pid_path);
    remove(log_path);
    
    if (rmdir(path) == -1) {
        perror("rmdir");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: clearly stop <container_id>\n");
        return 1;
    }

    char *container_name = argv[1];
    char pid_path[PATH_MAX];
    char container_path[PATH_MAX];

    if (snprintf(container_path, sizeof(container_path),
                "%s/%s", CONTAINERS_DIR, container_name) >= sizeof(container_path) ||
        snprintf(pid_path, sizeof(pid_path),
                "%s/pid", container_path) >= sizeof(pid_path)) {
        fprintf(stderr, "Path too long.\n");
        return 1;
    }

    FILE *f = fopen(pid_path, "r");
    if (!f) {
        fprintf(stderr, "Error: container '%s' not found.\n", container_name);
        return 1;
    }

    pid_t pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        fprintf(stderr, "Error: could not read PID for container '%s'.\n", container_name);
        return 1;
    }
    fclose(f);

    printf("Stopping container %s...\n", container_name);

    if (kill(pid, SIGTERM) == -1) {
        if (errno == ESRCH) {
            fprintf(stderr, "Container '%s' was not running.\n", container_name);
            remove_directory(container_path); // Clean up
            return 0;
        }
        perror("kill (SIGTERM)");
        return 1;
    }

    // Wait a few seconds for graceful shutdown
    sleep(3);

    // Check if the process is still running
    if (kill(pid, 0) == 0) {
        printf("Container did not stop gracefully. Sending SIGKILL...\n");
        if (kill(pid, SIGKILL) == -1 && errno != ESRCH) {
            perror("kill (SIGKILL)");
            return 1;
        }
    }
    
    printf("Container %s stopped.\n", container_name);

    // Cleanup
    remove_directory(container_path);

    return 0;
} 