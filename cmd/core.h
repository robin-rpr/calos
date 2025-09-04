/* Copyright © Triad National Security, LLC, and others.

   This interface contains Clearly's core containerization features. */

#define _GNU_SOURCE
#include <stdbool.h>


/** Types **/

enum bind_dep {
   BD_REQUIRED,  // both source and destination must exist
   BD_OPTIONAL,  // if either source or destination missing, do nothing
   BD_MAKE_DST,  // source must exist, try to create destination if it doesn't
};

struct bind {
   char *src;
   char *dst;
   enum bind_dep dep;
};

enum img_type {
   IMG_DIRECTORY,  // normal directory, perhaps an external mount of some kind
   IMG_SQUASH,     // SquashFS archive file (not yet mounted)
   IMG_NAME,       // name of image in storage
   IMG_NONE,       // image type is not set yet
};

struct container {
   long cgroup_pids_max;
   char *cgroup_cpu_weight;
   char *cgroup_memory_max;
   char *cgroup_cpu_max;
   char **allow_map_strs;   // egress traffic to allow
   struct bind *binds;      // mount paths to container
   gid_t gid;               // GID to use in container
   uid_t uid;               // UID to use in container
   char **command;          // command to run in container
   bool detached;           // detach container to background
   char *name;              // name of container in daemon
   bool env_expand;         // expand variables in --env
   char **argv;             // override command to run in container
   char *host_home;         // if --home, host path to user homedir, else NULL
   char **host_map_strs;    // hosts file mapping (HOSTNAME:IP_ADDRESS format)
   char *image;             // image description from command line
   char *ip;                // IP address to use in container
   bool join;               // is this a synchronized join?
   int join_ct;             // number of peers in a synchronized join
   pid_t join_pid;          // process in existing namespace to join
   char *join_tag;          // identifier for synchronized join
   char *overlay_size;      // size of overlaid tmpfs (NULL for no overlay)
   char **port_map_strs;    // container ports to publish (HOST:GUEST format)
   bool public_passwd;      // don't bind custom /etc/{passwd,group}
   bool private_tmp;        // don't bind host's /tmp
   char **cap_add;          // capabilities to add to container
   char **cap_drop;         // capabilities to drop from container
   char **sysctl_map_strs;  // kernel parameters to set (KEY=VALUE format)
   char **label_map_strs;   // container labels (KEY=VALUE format)
   enum img_type type;      // directory, SquashFS, etc.
   bool writable;           // re-mount image read-write
};


/** Function prototypes **/

void containerize(struct container *c, const char *runtime_dir, const char *mount_dir);
enum img_type image_type(const char *ref, const char *images_dir);
char *img_name2path(const char *name, const char *storage_dir);
void run_command(char *argv[], const char *initial_dir);
#ifdef HAVE_SECCOMP
void seccomp_install(void);
#endif
