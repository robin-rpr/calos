/* Copyright © Triad National Security, LLC, and others. */

#define _GNU_SOURCE
#include "config.h"
#include <stdarg.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#ifdef HAVE_SECCOMP
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#ifdef HAVE_SECCOMP
#include <stddef.h>
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif
#include <signal.h>
#include <time.h>
#include <unistd.h>


#include "misc.h"
#include "core.h"
#include "net.h"
#ifdef HAVE_LIBSQUASHFUSE
#include "fuse.h"
#endif


/** Macros **/

/* Timeout in seconds for waiting for join semaphore. */
#define JOIN_TIMEOUT 30

/* Maximum length of paths we’re willing to deal with. (Note that
   system-defined PATH_MAX isn't reliable.) */
#define PATH_CHARS 4096

/* Mount point for the tmpfs used by -W. We want this to be (a) always
   available [1], (b) short, (c) not used by anything else we care about
   during container setup, and (d) not wildly confusing if users see it in an
   error message. Must be a string literal because we use C’s literal

   concatenation feature. Options considered (all of these required by FHS):

      /boot       Not present if host is booted in some strange way?
      /etc        Likely very reliable but seems risky
      /mnt        Used for images on GitHub Actions and causes CI failures
      /opt        Seems very omittable
      /srv        I’ve never actually seen it used; reliable?
      /var        Too aggressive?
      /var/spool  Long; omittable for lightweight hosts?

   [1]: https://www.pathname.com/fhs/pub/fhs-2.3.pdf */
#define WF_MNT "/srv"


/** Constants **/

/* Default bind-mounts. */
struct bind BINDS_DEFAULT[] = {
   { "/dev",                     "/dev",                     BD_REQUIRED },
   { "/proc",                    "/proc",                    BD_REQUIRED },
   { "/sys",                     "/sys",                     BD_REQUIRED },
   { "/etc/machine-id",          "/etc/machine-id",          BD_OPTIONAL },
   /* Cray bind-mounts. See #1473. */
   { "/var/lib/hugetlbfs",       "/var/lib/hugetlbfs",       BD_OPTIONAL },
   /* Cray Gemini/Aries interconnect bind-mounts. */
   { "/etc/opt/cray/wlm_detect", "/etc/opt/cray/wlm_detect", BD_OPTIONAL },
   { "/opt/cray/wlm_detect",     "/opt/cray/wlm_detect",     BD_OPTIONAL },
   { "/opt/cray/alps",           "/opt/cray/alps",           BD_OPTIONAL },
   { "/opt/cray/udreg",          "/opt/cray/udreg",          BD_OPTIONAL },
   { "/opt/cray/ugni",           "/opt/cray/ugni",           BD_OPTIONAL },
   { "/opt/cray/xpmem",          "/opt/cray/xpmem",          BD_OPTIONAL },
   { "/var/opt/cray/alps",       "/var/opt/cray/alps",       BD_OPTIONAL },
   /* Cray Shasta/Slingshot bind-mounts. */
   { "/var/spool/slurmd",        "/var/spool/slurmd",        BD_OPTIONAL },
   { 0 }
};

/* Special values for seccomp tables. These must be negative to avoid clashing
   with real syscall numbers (note zero is often a valid syscal number). */
#define NR_NON -1  // syscall does not exist on architecture
#define NR_END -2  // end of table

/* Sentinel file descriptor for testing the seccomp filter with mknodat(2).
   This must always be a successful no-op, even if we grow stateful emulation.
   See: https://www.kernel.org/doc/Documentation/admin-guide/devices.txt */
#define FD_TEST_NOOP (AT_FDCWD - 1)

/* Architectures that we support for seccomp. Order matches the
   corresponding table below.

   Note: On some distros (e.g., CentOS 7), some of the architecture numbers
   are missing. The workaround is to use the numbers I have on Debian
   Bullseye. The reason I (Reid) feel moderately comfortable doing this is how
   militant Linux is about not changing the userspace API. */
#ifdef HAVE_SECCOMP
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7u  // undeclared on CentOS 7
#undef  AUDIT_ARCH_ARM                  // uses undeclared EM_ARM on CentOS 7
#define AUDIT_ARCH_ARM     0x40000028u
#endif
int SECCOMP_ARCHS[] = { AUDIT_ARCH_AARCH64,   // arm64
                        AUDIT_ARCH_ARM,       // arm32
                        AUDIT_ARCH_I386,      // x86 (32-bit)
                        AUDIT_ARCH_PPC64LE,   // PPC
                        AUDIT_ARCH_S390X,     // s390x
                        AUDIT_ARCH_X86_64,    // x86-64
                        NR_END };
#endif

/* System call numbers that we fake with seccomp (by doing nothing and
   returning success). Some processors can execute multiple architectures
   (e.g., 64-bit Intel CPUs can run both x64-64 and x86 code), and a process’
   architecture can even change (if you execve(2) binary of different
   architecture), so we can’t just use the build host’s architecture.

   I haven’t figured out how to gather these system call numbers
   automatically, so they are compiled from [1, 2, 3]. See also [4] for a more
   general reference.

   NOTE: The total number of faked syscalls (i.e., non-zero entries below)
   must be somewhat less than 256. I haven’t computed the exact limit. There
   will be an assertion failure at runtime if this is exceeded.

   WARNING: Keep this list consistent with the clearly image(1) man page!

   [1]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#Cross_arch-Numbers
   [2]: https://github.com/strace/strace/blob/v4.26/linux/powerpc64/syscallent.h
   [3]: https://github.com/strace/strace/blob/v6.6/src/linux/s390x/syscallent.h
   [4]: https://unix.stackexchange.com/questions/421750 */
#ifdef HAVE_SECCOMP
int FAKE_SYSCALL_NRS[][6] = {
   // arm64   arm32   x86     PPC64   s390x   x86-64
   // ------  ------  ------  ------  ------  ------
   {      91,    185,    185,    184,    185,    126 },  // capset
   {  NR_NON,    182,    182,    181,    212,     92 },  // chown
   {  NR_NON,    212,    212, NR_NON, NR_NON, NR_NON },  // chown32
   {      55,     95,     95,     95,    207,     93 },  // fchown
   {  NR_NON,    207,    207, NR_NON, NR_NON, NR_NON },  // fchown32
   {      54,    325,    298,    289,    291,    260 },  // fchownat
   {  NR_NON,     16,     16,     16,    198,     94 },  // lchown
   {  NR_NON,    198,    198, NR_NON, NR_NON, NR_NON },  // lchown32
   {     152,    139,    139,    139,    216,    123 },  // setfsgid
   {  NR_NON,    216,    216, NR_NON, NR_NON, NR_NON },  // setfsgid32
   {     151,    138,    138,    138,    215,    122 },  // setfsuid
   {  NR_NON,    215,    215, NR_NON, NR_NON, NR_NON },  // setfsuid32
   {     144,     46,     46,     46,    214,    106 },  // setgid
   {  NR_NON,    214,    214, NR_NON, NR_NON, NR_NON },  // setgid32
   {     159,     81,     81,     81,    206,    116 },  // setgroups
   {  NR_NON,    206,    206, NR_NON, NR_NON, NR_NON },  // setgroups32
   {     143,     71,     71,     71,    204,    114 },  // setregid
   {  NR_NON,    204,    204, NR_NON, NR_NON, NR_NON },  // setregid32
   {     149,    170,    170,    169,    210,    119 },  // setresgid
   {  NR_NON,    210,    210, NR_NON, NR_NON, NR_NON },  // setresgid32
   {     147,    164,    164,    164,    208,    117 },  // setresuid
   {  NR_NON,    208,    208, NR_NON, NR_NON, NR_NON },  // setresuid32
   {     145,     70,     70,     70,    203,    113 },  // setreuid
   {  NR_NON,    203,    203, NR_NON, NR_NON, NR_NON },  // setreuid32
   {     146,     23,     23,     23,    213,    105 },  // setuid
   {  NR_NON,    213,    213, NR_NON, NR_NON, NR_NON },  // setuid32
   { NR_END }, // end
};
int FAKE_MKNOD_NRS[] =
   {  NR_NON,     14,     14,     14,     14,    133 };
int FAKE_MKNODAT_NRS[] =
   {      33,    324,    297,    288,    290,    259 };
#endif


/** Global variables **/

/* Variables for coordinating --join. */
struct {
   bool winner_p;
   char *sem_name;
   sem_t *sem;
   char *shm_name;
   struct {
      pid_t winner_pid;  // access anytime after initialization (write-once)
      int proc_left_ct;  // access only while serial
   } *shared;
} join;

/* Bind mounts done so far; canonical host paths. If null, there are none. */
char **bind_mount_paths = NULL;

/* Path to the cgroup. */
char *cgroup_path = NULL;


/** Function prototypes (private) **/

void bind_mount(const char *src, const char *dst, enum bind_dep,
                const char *newroot, unsigned long flags, const char *scratch);
void bind_mounts(const struct bind *binds, const char *newroot,
                 unsigned long flags, const char * scratch);
void enter_udss(struct container *c);
#ifdef HAVE_SECCOMP
void iw(struct sock_fprog *p, int i,
        uint16_t op, uint32_t k, uint8_t jt, uint8_t jf);
#endif
void parse_host_map(const char* map_str, char** hostname, struct in_addr* ip_addr);
void parse_allow_map(const char* map_str, struct in_addr* ip_addr);
void parse_publish_map(const char* map_str, int* host_port, int* container_port);
void join_begin(const char *join_tag);
void join_namespace(pid_t pid, const char *ns);
void join_namespaces(pid_t pid);
void join_end(int join_ct);
void sem_timedwait_relative(sem_t *sem, int timeout);
void setup_passwd(const struct container *c);
void setup_namespaces(const struct container *c, uid_t uid_out, uid_t uid_in,
                      gid_t gid_out, gid_t gid_in);
void tmpfs_mount(const char *dst, const char *newroot, const char *data);
bool pull_image(const char *ref, const char *storage_dir);
void cgroup_init(const struct container *c);
void cgroup_cleanup(void);


/** Functions **/

/* Bind-mount the given path into the container image. */
void bind_mount(const char *src, const char *dst, enum bind_dep dep,
                const char *newroot, unsigned long flags, const char *scratch) {
   char *dst_fullc, *newrootc;
   char *dst_full = cat(newroot, dst);

   Te (src[0] != 0 && dst[0] != 0 && newroot[0] != 0, "empty string");
   Te (dst[0] == '/' && newroot[0] == '/', "relative path");

   if (!path_exists(src, NULL, true)) {
      Te (dep == BD_OPTIONAL, "can't bind: source not found: %s", src);
      return;
   }

   if (!path_exists(dst_full, NULL, true))
      switch (dep) {
      case BD_REQUIRED:
         FATAL(0, "can't bind: destination not found: %s", dst_full);
         break;
      case BD_OPTIONAL:
         return;
      case BD_MAKE_DST:
         mkdirs(newroot, dst, bind_mount_paths, scratch);
         break;
      }

   newrootc = realpath_(newroot, false);
   dst_fullc = realpath_(dst_full, false);
   Tf (path_subdir_p(newrootc, dst_fullc),
       "can't bind: %s not subdirectory of %s", dst_fullc, newrootc);
   if (strcmp(newroot, "/"))  // don't record if newroot is "/"
      list_append((void **)&bind_mount_paths, &dst_fullc, sizeof(char *));

   Zf (mount(src, dst_full, NULL, MS_REC|MS_BIND|flags, NULL),
       "can't bind %s to %s", src, dst_full);
}

/* Bind-mount a null-terminated array of struct bind objects. */
void bind_mounts(const struct bind *binds, const char *newroot,
                 unsigned long flags, const char * scratch) {
   for (int i = 0; binds[i].src != NULL; i++)
      bind_mount(binds[i].src, binds[i].dst, binds[i].dep,
                 newroot, flags, scratch);
}

/* Set up new namespaces or join existing ones.
 *
 * This function orchestrates the creation of a new container environment by
 * forking the current process. The parent and child then cooperate to
 * construct the isolated environment.
 *
 * The high-level process is as follows:
 * 1. A socket pair is created to serve as a synchronization channel between
 * the parent and the forthcoming child process.
 * 2. The process forks (double-fork if detached).
 * 3. The parent process is responsible for configuring the host-side
 * networking. This includes creating a virtual Ethernet (veth) pair,
 * attaching one end to a shared bridge, and setting up network address
 * translation (NAT) rules. It then waits for a signal from the child
 * before moving the other end of the veth pair into the child's newly
 * created network namespace. Finally, it waits for the child to terminate.
 * 4. The child process is responsible for creating and entering the new
 * namespaces (user, mount, network). After entering the namespaces, it
 * signals the parent. Once the parent completes the network setup, the
 * child configures its own network interface, drops privileges, and
 * prepares the container's filesystem by populating /etc/resolv.conf and
 * /etc/hosts. Execution then returns to main(), which will run the user's
 * command inside the fully-formed container.
 */
void containerize(
   struct container *c,
   const char *runtime_dir
) {
    uid_t host_uid = geteuid();
    gid_t host_gid = getegid();
    int sync_pipe[2];

    // Detach from terminal.
    if (c->detached) {
        pid_t pid = fork();
        if (pid > 0) {
            exit(0);
        }
        setsid();
    }

    // Network configuration.
    const char *bridge_name = "clearly0";
    const char *veth_host_prefix = "vethe";
    const char *veth_peer_prefix = "if";
    const char *veth_guest_name = "eth0";

    const int cidr = 8;
    char network_cidr[18];
    char hostname[256];

    struct in_addr subnet_ip = { .s_addr = inet_addr("10.0.0.0") };
    struct in_addr bridge_ip = { .s_addr = inet_addr("10.0.0.1") };
    struct in_addr guest_ip  = { .s_addr = 0 };
    
    // Get network cidr.
    snprintf(network_cidr, sizeof(network_cidr), "%s/%d", inet_ntoa(subnet_ip), cidr);

    // Get hostname.
    if (gethostname(hostname, sizeof(hostname)) != 0) {
      strncpy(hostname, "unknown", sizeof(hostname));
   }

   /* Step 1: Ensure the network bridge exists.
      The bridge provides a virtual switch for containers to communicate with each other
      and the host. If the bridge does not exist, create it and assign it the bridge IP. */
   if (!is_bridge_exists(bridge_name)) {
      create_bridge(bridge_name, &bridge_ip, cidr);
   }

   /* Step 2: Generate a unique IP for the container.
       To minimize network conflicts, especially in multi-tenant systems, we
       generate a pseudo-random but deterministic IP address. The address is
       derived from a hash of the host's name combined with the process ID.
       This distributes containers across the 10.0.0.0/8 address space. The
       format is 10.H.P.X, where H is from the host hash, P is from the PID,
       and X is a combination. We then send an ARP request to ensure the
       address is not currently in use on the local network segment. If it is,
       we linearly probe for the next available address. */
   while (1) {         
      // Create a hash from hostname.
      uint32_t host_hash = 0;
      for (char *p = hostname; *p; p++) {
         host_hash = host_hash * 31 + *p;
      }
      
      // Get process ID
      pid_t pid = getpid();
      
      // Calculate IP within 10.0.0.0/8 range
      // Format: 10.H.P.X where:
      // H = host_hash byte
      // P = pid byte
      // X = (host_hash + pid) byte
      uint32_t h = (host_hash & 0xFF);
      uint32_t p = (pid & 0xFF);
      uint32_t x = ((host_hash + pid) & 0xFF);
      
      // Ensure we don't use 0 or 255 for any octet
      h = (h == 0 || h == 255) ? 1 : h;
      p = (p == 0 || p == 255) ? 1 : p;
      x = (x == 0 || x == 255) ? 1 : x;
      
      // Combine into final IP: 10.H.P.X
      uint32_t ip = (10 << 24) | (h << 16) | (p << 8) | x;
      
      // Convert to network byte order.
      guest_ip.s_addr = htonl(ip);

      // Send ARP Request.
      if (send_arp(&guest_ip, bridge_name, &bridge_ip) == 0) {
         /* IP Address is available, break. */
         break;
      } else {
         /* Not available, try the next one. */
         uint32_t ip = ntohl(guest_ip.s_addr);
         ip = ((ip + 1) & 0x00FFFFFF) | 0x0A000000;
         guest_ip.s_addr = htonl(ip);
      }
   }

    // Use a pipe to synchronize parent and child. The child will write to the
    // pipe only after it has entered its new namespaces.
    Zf(socketpair(AF_UNIX, SOCK_STREAM, 0, sync_pipe) == -1, "failed to create sync socketpair");

    pid_t child_pid = fork();
    Zf(child_pid == -1, "failed to fork");

    if (child_pid > 0) {
        /* Parent process */
        close(sync_pipe[1]);

        // Ensure veth link pair.
        char veth_host_name[IFNAMSIZ]; // Host-side veth name.
        char veth_peer_name[IFNAMSIZ]; // Peer-side veth name (container-side).
        snprintf(veth_host_name, IFNAMSIZ, "%s%06d", veth_host_prefix, child_pid % 1000000);
        snprintf(veth_peer_name, IFNAMSIZ, "%s%06d", veth_peer_prefix, child_pid % 1000000);
        create_veth_pair(veth_host_name, veth_peer_name);
        set_veth_bridge(veth_host_name, bridge_name);
        set_veth_up(veth_host_name);

        // Ensure SNAT (Source NAT) Masquerade.
        if (!is_nft_masquerade_exists(&subnet_ip)) {
            create_nft_masquerade(&subnet_ip, cidr); 
        }

        // Ensure DNAT (Destination NAT) Filter.
        if (!is_nft_filter_exists(&subnet_ip)) {
            VERBOSE("creating DNAT (Destination NAT) Filter");
            create_nft_filter(&subnet_ip, cidr);
        }

        flush_nft_filter(&guest_ip);

        for (int i = 0; c->allow_map_strs[i] != NULL; i++) {
            struct in_addr ip_addr;
            parse_allow_map(c->allow_map_strs[i], &ip_addr);
            set_nft_filter_allow(&ip_addr, &guest_ip); // Send
            set_nft_filter_allow(&guest_ip, &ip_addr); // Receive
        }

        // Ensure DNAT (Destination NAT) Forward.
        flush_nft_forward(&guest_ip, "tcp");
        flush_nft_forward(&guest_ip, "udp");

        for (int i = 0; c->publish_map_strs[i] != NULL; i++) {
            int host_port, guest_port;
            parse_publish_map(c->publish_map_strs[i], &host_port, &guest_port);
            create_nft_forward(&guest_ip, host_port, guest_port, "tcp");
            create_nft_forward(&guest_ip, host_port, guest_port, "udp");
        }
        
        /* Step 3: Synchronize with child.
           Wait for the child to signal 'S' (sync), indicating it has created
           its namespaces. Then, move the veth peer into the child's network
           namespace and signal 'R' (ready) to allow the child to proceed. */
        char buf;
        Zf(read(sync_pipe[0], &buf, 1) != 1 || buf != 'S', "failed to sync with child");

        // Move veth peer into child's network namespace.
        // This is the last step before the child can proceed.
        set_veth_ns_pid(veth_peer_name, child_pid);

        /* Step 4: Signal child to proceed.
           The parent writes 'R' (ready) to the pipe to notify the child that
           network setup is complete and it can continue. The child will read
           this signal before proceeding. */
        Zf(write(sync_pipe[0], "R", 1) != 1, "failed to signal child");
        close(sync_pipe[0]);

        // Ignore SIGHUP.
        signal(SIGHUP, SIG_IGN);

        /* Step 10: Wait for child to exit.
           We wait for the child to exit so we can perform cleanup. */
        int status;
        waitpid(child_pid, &status, 0);

        /* Step 11: Cleanup.
           Various cleanup tasks to leave the system in a clean state.
           Without this, the system will be left in a dirty state where the
           child process is still thought to exist and the parent process has
           lingering registered resources. */
        VERBOSE("performing cleanup");

        // Exit.
        exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);

    } else {
        /* Child process */
        close(sync_pipe[0]);

        if (c->detached) {
            char path[PATH_CHARS];
            char log_path[PATH_CHARS];
            char net_path[PATH_CHARS];
            char pid_path[PATH_CHARS];
            
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
            snprintf(path, sizeof(path), "/run/clearly/%s", c->name);
            snprintf(log_path, sizeof(log_path), "%s/log", path);
            snprintf(net_path, sizeof(net_path), "%s/net", path);
            snprintf(pid_path, sizeof(pid_path), "%s/pid", path);
#pragma GCC diagnostic pop
            
            mkdirs("/run", cat("/clearly/", c->name), NULL, NULL);

            // Redirect stdout and stderr to the log file.
            T_ (1 <= dup2(open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644), STDOUT_FILENO));
            T_ (1 <= dup2(open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644), STDERR_FILENO));

            // Write IP to file.
            T_ (1 <= dprintf(open(net_path, O_WRONLY | O_CREAT | O_TRUNC, 0644), "%s", inet_ntoa(guest_ip)));

            // Write PID to file.
            T_ (1 <= dprintf(open(pid_path, O_WRONLY | O_CREAT | O_TRUNC, 0644), "%d", getpid()));
        }

        // Initialize cgroup.
        cgroup_init(c);
        Z_ (atexit(cgroup_cleanup));

        if (c->join_pid) {
            // Join existing container.
            join_namespaces(c->join_pid);
            return;
        }

        if (c->join) {
            // Begin capabilities for joining.
            join_begin(c->join_tag);
        }

        if (!c->join || join.winner_p) {
            // Set up user and mount namespaces. This is a two-step process to
            // gain the privileges needed to prepare the new root filesystem.
            setup_namespaces(c, host_uid, 0, host_gid, 0);
#ifdef HAVE_LIBSQUASHFUSE
            if (c->type == IMG_SQUASH)
                sq_fork(c);
#endif
            // Remap to the final container user and group IDs.
            setup_namespaces(c, 0, c->uid, 0, c->gid);
            enter_udss(c);
        } else {
            // This is a loser in a --join race.
            join_namespaces(join.shared->winner_pid);
        }

        if (c->join) {
            // End capabilities for joining.
            join_end(c->join_ct);
        }

        /* Step 5: Synchronize with parent.
           Signal 'S' (sync) to the parent, indicating namespace setup is
           complete. Then wait for the parent to send 'R' (ready) after it
           has moved the veth interface into our namespace. */
        Zf(write(sync_pipe[1], "S", 1) != 1, "child failed to send sync signal");

        /* Step 6: Wait for parent to move veth interface.
           The child reads 'R' (ready) from the pipe to wait for the parent
           to move the veth interface into our namespace. After this, the child
           can proceed until it exits. */
        char ack;
        Zf(read(sync_pipe[1], &ack, 1) != 1 || ack != 'R', "child failed to receive ready signal");
        close(sync_pipe[1]);

        // Retrieve our veth peer name.
        char veth_peer_name[IFNAMSIZ];
        snprintf(veth_peer_name, IFNAMSIZ, "%s%06d", veth_peer_prefix, getpid() % 1000000);

        // Configure veth link peer.
        set_veth_name(veth_peer_name, veth_guest_name);
        set_veth_ip(veth_guest_name, &guest_ip, cidr);
        set_veth_mac(veth_guest_name); // Is Random.
        set_veth_up(veth_guest_name);

        // Configure loopback interface.
        set_veth_up("lo");

        // Configure default route.
        set_veth_route(veth_guest_name, &bridge_ip, "0.0.0.0/0");

        VERBOSE("child network configured");

        /* Step 7: Drop elevated capabilities.
           The CAP_NET_ADMIN capability was required to configure the network
           interfaces. As it is no longer needed, we drop it to adhere to the
           principle of least privilege. */
#ifdef HAVE_LIBCAP
        cap_t caps;
        Tf( (caps = cap_get_proc()) != NULL, "can't get capabilities");
        cap_value_t cap_list[1] = { CAP_NET_ADMIN };
        Zf(cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR), "can't clear effective capability");
        Zf(cap_set_flag(caps, CAP_PERMITTED, 1, cap_list, CAP_CLEAR), "can't clear permitted capability");
        Zf(cap_set_proc(caps), "can't set capabilities");
        Zf(cap_free(caps), "can't free capabilities");
        VERBOSE("dropped NET_ADMIN capability");
#endif

        /* Step 8: Configure DNS.
           We add two nameservers to /etc/resolv.conf: Google's DNS and Cloudflare's DNS.
           This provides a basic DNS resolution mechanism for the container. */
        FILE *resolv_conf = fopen("/etc/resolv.conf", "w");
        if (resolv_conf != NULL) {
            fprintf(resolv_conf, "nameserver 8.8.8.8\n"); // Google DNS
            fprintf(resolv_conf, "nameserver 1.1.1.1\n"); // Cloudflare DNS
            fclose(resolv_conf);
        }

        /* Step 9: Configure /etc/hosts.
           We add hostname entries to /etc/hosts to enable basic hostname
           resolution within the container. This is a simple mechanism to
           allow containers to resolve hostnames to IP addresses. */
        for (int i = 0; c->host_map_strs[i] != NULL; i++) {
            char *hostname;
            struct in_addr ip_addr;
            parse_host_map(c->host_map_strs[i], &hostname, &ip_addr);

            char *hosts_path = cat(c->newroot, "/etc/hosts");
            FILE *hosts_file = fopen(hosts_path, "a");
            if (hosts_file && fprintf(hosts_file, "%s %s\n", inet_ntoa(ip_addr), hostname) > 0) {
                VERBOSE("adding host entry %s %s to /etc/hosts", inet_ntoa(ip_addr), hostname);
            } else {
                WARNING("failed to write to /etc/hosts: %s", hosts_path);
            }
            if (hosts_file) fclose(hosts_file);
            free(hosts_path);
            free(hostname);
        }
    }
}

/* Enter the new root (UDSS). On entry, the namespaces are set up, and this
   does the mounting and filesystem setup.

   Note that pivot_root(2) requires a complex dance to work, i.e., to avoid
   multiple undocumented error conditions. This dance is explained in detail
   in bin/check.c. */
void enter_udss(struct container *c)
{
   char *nr_parent, *nr_base, *mkdir_scratch;

   LOG_IDS;
   mkdir_scratch = NULL;
   path_split(c->newroot, &nr_parent, &nr_base);

   // Claim new root for this namespace. Despite MS_REC in bind_mount(), we do
   // need both calls to avoid pivot_root(2) failing with EBUSY later.
   DEBUG("claiming new root for this namespace")
   bind_mount(c->newroot, c->newroot, BD_REQUIRED, "/", MS_PRIVATE, NULL);
   bind_mount(nr_parent, nr_parent, BD_REQUIRED, "/", MS_PRIVATE, NULL);
   // Re-mount new root read-only unless --write or already read-only.
   if (!c->writable && !(access(c->newroot, W_OK) == -1 && errno == EROFS)) {
      unsigned long flags =   path_mount_flags(c->newroot)
                            | MS_REMOUNT  // Re-mount ...
                            | MS_BIND     // only this mount point ...
                            | MS_RDONLY;  // read-only.
      Z_ (mount(NULL, c->newroot, NULL, flags, NULL));
   }
   // Overlay a tmpfs if --write-fake. See for useful details:
   // https://www.kernel.org/doc/html/v5.11/filesystems/tmpfs.html
   // https://www.kernel.org/doc/html/v5.11/filesystems/overlayfs.html
   if (c->overlay_size != NULL) {
      char *options;
      struct stat st;
      VERBOSE("overlaying tmpfs for --write-fake (%s)", c->overlay_size);
      T_ (1 <= asprintf(&options, "size=%s", c->overlay_size));
      Zf (mount(NULL, WF_MNT, "tmpfs", 0, options),
          "cannot mount tmpfs for overlay");
      free(options);
      Z_ (mkdir(WF_MNT "/upper", 0700));
      Z_ (mkdir(WF_MNT "/work", 0700));
      Z_ (mkdir(WF_MNT "/merged", 0700));
      mkdir_scratch = WF_MNT "/mkdir_overmount";
      Z_ (mkdir(mkdir_scratch, 0700));
      T_ (1 <= asprintf(&options, ("lowerdir=%s,upperdir=%s,workdir=%s,"
                                   "index=on,userxattr,volatile"),
                        c->newroot, WF_MNT "/upper", WF_MNT "/work"));
      // update newroot
      Zf (stat(c->newroot, &st),
          "can't stat new root; overmounted by tmpfs for -W?: %s", c->newroot);
      c->newroot = WF_MNT "/merged";
      free(nr_parent);
      free(nr_base);
      path_split(c->newroot, &nr_parent, &nr_base);
      Zf (mount(NULL, c->newroot, "overlay", 0, options),
          "can't overlay: %s, %s", c->newroot, options);
      VERBOSE("newroot updated: %s", c->newroot);
      free(options);
   }
   DEBUG("starting bind-mounts");
   // Bind-mount default files and directories.
   bind_mounts(BINDS_DEFAULT, c->newroot, MS_RDONLY, NULL);
   // /etc/passwd and /etc/group.
   if (c->public_passwd)
      setup_passwd(c);
   // Container /tmp.
   if (c->private_tmp) {
      tmpfs_mount("/tmp", c->newroot, NULL);
   } else {
      bind_mount(host_tmp, "/tmp", BD_REQUIRED, c->newroot, 0, NULL);
   }
   // Bind-mount user’s home directory at /home/$USER if requested.
   if (c->host_home) {
      T_ (c->overlay_size != NULL);
      bind_mount(c->host_home, cat("/home/", username),
                 BD_MAKE_DST, c->newroot, 0, mkdir_scratch);
   }
   // Bind-mount user-specified directories.
   bind_mounts(c->binds, c->newroot, 0, mkdir_scratch);
   // Overmount / to avoid EINVAL if it’s a rootfs.
   Z_ (chdir(nr_parent));
   Z_ (mount(nr_parent, "/", NULL, MS_MOVE, NULL));
   Z_ (chroot("."));
   // Pivot into the new root. Use /dev because it’s available even in
   // extremely minimal images.
   c->newroot = cat("/", nr_base);
   Zf (chdir(c->newroot), "can't chdir into new root");
   Zf (syscall(SYS_pivot_root, c->newroot, path_join(c->newroot, "dev")),
       "can't pivot_root(2)");
   Zf (chroot("."), "can't chroot(2) into new root");
   Zf (umount2("/dev", MNT_DETACH), "can't umount old root");
   DEBUG("pivot_root(2) dance successful")
}

/* Return image type of path, or exit with error if not a valid type. */
enum img_type image_type(const char *ref, const char *storage_dir)
{
   struct stat st;
   FILE *fp;
   char magic[4];  // four bytes, not a string

   // If there’s a directory in storage where we would expect there to be if
   // ref were an image name, assume it really is an image name.
   if (path_exists(img_name2path(ref, storage_dir), NULL, false))
      return IMG_NAME;

   // Now we know ref is a path of some kind, so find it.
   if (stat(ref, &st) != 0) {
      // If stat fails, we assume the image is not local and try to pull it.
      if (pull_image(ref, storage_dir)) {
         if (path_exists(img_name2path(ref, storage_dir), NULL, false))
            return IMG_NAME;
      }
      // If we get here, either pull failed or the image still doesn't exist
      Zf (stat(ref, &st), "can't stat: %s", ref);
   }

   // If ref is the path to a directory, then it’s a directory.
   if (S_ISDIR(st.st_mode))
      return IMG_DIRECTORY;

   // Now we know it’s file-like enough to read. See if it has the SquashFS
   // magic number.
   fp = fopen(ref, "rb");
   Tf (fp != NULL, "can't open: %s", ref);
   Tf (fread(magic, sizeof(char), 4, fp) == 4, "can't read: %s", ref);
   Zf (fclose(fp), "can't close: %s", ref);
   VERBOSE("image file magic expected: 6873 7173; actual: %x%x %x%x",
           magic[0], magic[1], magic[2], magic[3]);

   // If magic number matches, it’s a squash. Note: Magic number is 6873 7173,
   // i.e. “hsqs”. I think “sqsh” was intended but the superblock designers
   // were confused about endianness.
   // See: https://dr-emann.github.io/squashfs/
   if (memcmp(magic, "hsqs", 4) == 0)
      return IMG_SQUASH;

   // Well now we’re stumped.
   FATAL(0, "unknown image type: %s", ref);
}

char *img_name2path(const char *name, const char *storage_dir){
   char *path;
   char *name_fs = strdup(name);

   replace_char(name_fs, '/', '%');
   replace_char(name_fs, ':', '+');

   T_ (1 <= asprintf(&path, "%s/img/%s", storage_dir, name_fs));

   free(name_fs);  // make Tim happy
   return path;
}

/* Helper function to write seccomp-bpf programs. */
#ifdef HAVE_SECCOMP
void iw(struct sock_fprog *p, int i,
        uint16_t op, uint32_t k, uint8_t jt, uint8_t jf)
{
   p->filter[i] = (struct sock_filter){ op, jt, jf, k };
   DEBUG("%4d: { op=%2x k=%8x jt=%3d jf=%3d }", i, op, k, jt, jf);
}
#endif

/* Helper function to parse "hostname:ip_address" string. */
void parse_host_map(const char* map_str, char** hostname, struct in_addr* ip_addr) {
    char* str = strdup(map_str);
    char* colon = strchr(str, ':');
    Tf(colon != NULL, "invalid host entry format. Expected HOSTNAME:IP_ADDRESS");
    *colon = '\0';
    *hostname = strdup(str); // Allocate memory for hostname
    Tf(inet_pton(AF_INET, colon + 1, ip_addr) == 1, "invalid IP address in host entry");
    free(str);
}

/* Helper function to parse "DST" string. */
void parse_allow_map(const char* map_str, struct in_addr* ip_addr) {
    char* str = strdup(map_str);
    Tf(inet_pton(AF_INET, str, ip_addr) == 1, "invalid IP address in allow entry");
    free(str);
}

/* Helper function to parse "HOST_PORT:CONTAINER_PORT" string. */
void parse_publish_map(const char* map_str, int* host_port, int* container_port) {
    char* str = strdup(map_str);
    char* colon = strchr(str, ':');
    Tf(colon != NULL, "invalid port entry format. Expected HOST_PORT:CONTAINER_PORT");
    *colon = '\0';
    *host_port = atoi(str);
    *container_port = atoi(colon + 1);
    Tf(*host_port > 0 && *host_port < 65536, "invalid host port number");
    Tf(*container_port > 0 && *container_port < 65536, "invalid container port number");
    free(str);
}

/* Begin coordinated section of namespace joining. */
void join_begin(const char *join_tag) {
   int fd;

   join.sem_name = cat("/run_sem-", join_tag);
   join.shm_name = cat("/run_shm-", join_tag);

   // Serialize.
   join.sem = sem_open(join.sem_name, O_CREAT, 0600, 1);
   T_ (join.sem != SEM_FAILED);
   sem_timedwait_relative(join.sem, JOIN_TIMEOUT);

   // Am I the winner?
   fd = shm_open(join.shm_name, O_CREAT|O_EXCL|O_RDWR, 0600);
   if (fd > 0) {
      VERBOSE("join: I won");
      join.winner_p = true;
      Z_ (ftruncate(fd, sizeof(*join.shared)));
   } else if (errno == EEXIST) {
      VERBOSE("join: I lost");
      join.winner_p = false;
      fd = shm_open(join.shm_name, O_RDWR, 0);
      T_ (fd > 0);
   } else {
      T_ (0);
   }

   join.shared = mmap(NULL, sizeof(*join.shared), PROT_READ|PROT_WRITE,
                      MAP_SHARED, fd, 0);
   T_ (join.shared != NULL);
   Z_ (close(fd));

   // Winner keeps lock; losers parallelize (winner will be done by now).
   if (!join.winner_p)
      Z_ (sem_post(join.sem));
}

/* End coordinated section of namespace joining. */
void join_end(int join_ct) {
   if (join.winner_p) {                                // winner still serial
      VERBOSE("join: winner initializing shared data");
      join.shared->winner_pid = getpid();
      join.shared->proc_left_ct = join_ct;
   } else                                              // losers serialize
      sem_timedwait_relative(join.sem, JOIN_TIMEOUT);

   join.shared->proc_left_ct--;
   VERBOSE("join: %d peers left excluding myself", join.shared->proc_left_ct);

   if (join.shared->proc_left_ct <= 0) {
      VERBOSE("join: cleaning up IPC resources");
      Te (join.shared->proc_left_ct == 0, "expected 0 peers left but found %d",
          join.shared->proc_left_ct);
      Zf (sem_unlink(join.sem_name), "can't unlink sem: %s", join.sem_name);
      Zf (shm_unlink(join.shm_name), "can't unlink shm: %s", join.shm_name);
   }

   Z_ (sem_post(join.sem));  // parallelize (all)

   Z_ (munmap(join.shared, sizeof(*join.shared)));
   Z_ (sem_close(join.sem));

   VERBOSE("join: done");
}

/* Join a specific namespace. */
void join_namespace(pid_t pid, const char *ns) {
   char *path;
   int fd;

   T_ (1 <= asprintf(&path, "/proc/%d/ns/%s", pid, ns));
   fd = open(path, O_RDONLY);
   if (fd == -1) {
      if (errno == ENOENT) {
         Te (0, "join: no PID %d: %s not found", pid, path);
      } else {
         Tf (0, "join: can't open %s", path);
      }
   }
   /* setns(2) seems to be involved in some kind of race with syslog(3).
      Rarely, when configured with --enable-syslog, the call fails with
      EINVAL. We never figured out a proper fix, so just retry a few times in
      a loop. See issue #1270. */
   for (int i = 1; setns(fd, 0) != 0; i++)
      if (i >= 5) {
         Tf (0, "can’t join %s namespace of pid %d", ns, pid);
      } else {
         WARNING("can’t join %s namespace; trying again", ns);
         sleep(1);
      }
}

/* Join the existing namespaces created by the join winner. */
void join_namespaces(pid_t pid) {
   VERBOSE("joining namespaces of pid %d", pid);
   join_namespace(pid, "user");
   join_namespace(pid, "mnt");
}

/* Replace the current process with user command and arguments. */
void run_command(char *argv[], const char *initial_dir) {
   LOG_IDS;

   if (initial_dir != NULL)
      Zf (chdir(initial_dir), "can't cd to %s", initial_dir);

   VERBOSE("executing: %s", argv_to_string(argv));

   Zf (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "can't set no_new_privs");
   if (verbose < LL_INFO)
      T_ (freopen("/dev/null", "w", stdout));
   if (verbose < LL_STDERR)
      T_ (freopen("/dev/null", "w", stderr));
   execvp(argv[0], argv);  // only returns if error
   ERROR(errno, "can't execve(2): %s", argv[0]);
   exit(EXIT_CMD);
}

/* Set up the fake-syscall seccomp(2) filter. This computes and installs a
   long-ish but fairly simple BPF program to implement the filter. To
   understand this rather hairy language:

     1. https://man7.org/training/download/secisol_seccomp_slides.pdf
     2. https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
     3. https://elixir.bootlin.com/linux/latest/source/samples/seccomp */
#ifdef HAVE_SECCOMP
void seccomp_install(void) {
   int arch_ct = sizeof(SECCOMP_ARCHS)/sizeof(SECCOMP_ARCHS[0]) - 1;
   int syscall_cts[arch_ct];
   struct sock_fprog p = { 0 };
   int ii, idx_allow, idx_fake, idx_mknod, idx_mknodat, idx_next_arch;
   // Lengths of certain instruction groups. These are all obtained manually
   // by counting below, violating DRY. We could automate these counts, but it
   // seemed like the cost of extra buffers and code to do that would exceed
   // that of maintaining the manual counts.
   int ct_jump_start = 4;  // ld arch & syscall nr, arch test, end-of-arch jump
   int ct_mknod_jump = 2;  // jump table handling for mknod(2) and mknodat(2)
   int ct_mknod = 2;       // mknod(2) handling
   int ct_mknodat = 6;     // mknodat(2) handling

   // Count how many syscalls we are going to fake in the standard way. We
   // need this to compute the right offsets for all the jumps.
   for (int ai = 0; SECCOMP_ARCHS[ai] != NR_END; ai++) {
      p.len += ct_jump_start + ct_mknod_jump;
      syscall_cts[ai] = 0;
      for (int si = 0; FAKE_SYSCALL_NRS[si][0] != NR_END; si++) {
         bool syscall_p = FAKE_SYSCALL_NRS[si][ai] != NR_NON;
         syscall_cts[ai] += syscall_p;
         p.len += syscall_p;  // syscall jump table entry
      }
      DEBUG("seccomp: arch %x: found %d syscalls",
            SECCOMP_ARCHS[ai], syscall_cts[ai]);
   }

   // Initialize program buffer.
   p.len += (  1             // return allow
             + 1             // return fake success
             + ct_mknod      // mknod(2) handling
             + ct_mknodat);  // mknodat(2) handling
   DEBUG("seccomp(2) program has %d instructions", p.len);
   T_ (p.filter = calloc(p.len, sizeof(struct sock_filter)));

   // Return call addresses. Allow needs to come first because we’ll jump to
   // it for unknown architectures.
   idx_allow =   p.len - 2 - ct_mknod - ct_mknodat;
   idx_fake =    p.len - 1 - ct_mknod - ct_mknodat;
   idx_mknod =   p.len     - ct_mknod - ct_mknodat;
   idx_mknodat = p.len                - ct_mknodat;

   // Build a jump table for each architecture. The gist is: if architecture
   // matches, fall through into the jump table, otherwise jump to the next
   // architecture (or ALLOW for the last architecture).
   ii = 0;
   idx_next_arch = -1;  // avoid warning on some compilers
   for (int ai = 0; SECCOMP_ARCHS[ai] != NR_END; ai++) {
      int jump;
      idx_next_arch = ii + syscall_cts[ai] + ct_jump_start + ct_mknod_jump;
      // load arch into accumulator
      iw(&p, ii++, BPF_LD|BPF_W|BPF_ABS,
         offsetof(struct seccomp_data, arch), 0, 0);
      // jump to next arch if arch doesn't match
      jump = idx_next_arch - ii - 1;
      T_ (jump <= 255);
      iw(&p, ii++, BPF_JMP|BPF_JEQ|BPF_K, SECCOMP_ARCHS[ai], 0, jump);
      // load syscall number into accumulator
      iw(&p, ii++, BPF_LD|BPF_W|BPF_ABS,
         offsetof(struct seccomp_data, nr), 0, 0);
      // jump table of syscalls
      for (int si = 0; FAKE_SYSCALL_NRS[si][0] != NR_END; si++) {
         int nr = FAKE_SYSCALL_NRS[si][ai];
         if (nr != NR_NON) {
            jump = idx_fake - ii - 1;
            T_ (jump <= 255);
            iw(&p, ii++, BPF_JMP|BPF_JEQ|BPF_K, nr, jump, 0);
         }
      }
      // jump to mknod(2) handling (add even if syscall not implemented to
      // make the instruction counts simpler)
      jump = idx_mknod - ii - 1;
      T_ (jump <= 255);
      iw(&p, ii++, BPF_JMP|BPF_JEQ|BPF_K, FAKE_MKNOD_NRS[ai], jump, 0);
      // jump to mknodat(2) handling
      jump = idx_mknodat - ii - 1;
      T_ (jump <= 255);
      iw(&p, ii++, BPF_JMP|BPF_JEQ|BPF_K, FAKE_MKNODAT_NRS[ai], jump, 0);
      // unfiltered syscall, jump to allow (limit of 255 doesn’t apply to JA)
      jump = idx_allow - ii - 1;
      iw(&p, ii++, BPF_JMP|BPF_JA, jump, 0, 0);
   }
   T_ (idx_next_arch == idx_allow);

   // Returns. (Note that if we wanted a non-zero errno, we’d bitwise-or with
   // SECCOMP_RET_ERRNO. But because fake success is errno == 0, we don’t need
   // a no-op “| 0”.)
   T_ (ii == idx_allow);
   iw(&p, ii++, BPF_RET|BPF_K, SECCOMP_RET_ALLOW, 0, 0);
   T_ (ii == idx_fake);
   iw(&p, ii++, BPF_RET|BPF_K, SECCOMP_RET_ERRNO, 0, 0);

   // mknod(2) handling. This just loads the file mode and jumps to the right
   // place in the mknodat(2) handling.
   T_ (ii == idx_mknod);
   // load mode argument into accumulator
   iw(&p, ii++, BPF_LD|BPF_W|BPF_ABS,
                offsetof(struct seccomp_data, args[1]), 0, 0);
   // jump to mode test
   iw(&p, ii++, BPF_JMP|BPF_JA, 1, 0, 0);

   // mknodat(2) handling.
   T_ (ii == idx_mknodat);
   // load mode argument into accumulator
   iw(&p, ii++, BPF_LD|BPF_W|BPF_ABS,
                offsetof(struct seccomp_data, args[2]), 0, 0);
   // jump to fake return if trying to create a device.
   // WARNING: If you are here to add stateful emulation for mknodat(2), make
   // sure that file descriptor FD_TEST_NOOP remains a successful no-op, to
   // avoid silently invalidating the filter test below.
   iw(&p, ii++, BPF_ALU|BPF_AND|BPF_K, S_IFMT, 0, 0);   // file type only
   iw(&p, ii++, BPF_JMP|BPF_JEQ|BPF_K, S_IFCHR, 2, 0);
   iw(&p, ii++, BPF_JMP|BPF_JEQ|BPF_K, S_IFBLK, 1, 0);
   // returns
   iw(&p, ii++, BPF_RET|BPF_K, SECCOMP_RET_ALLOW, 0, 0);
   iw(&p, ii++, BPF_RET|BPF_K, SECCOMP_RET_ERRNO, 0, 0);

   // Install filter. Use prctl(2) rather than seccomp(2) for slightly greater
   // compatibility (Linux 3.5 rather than 3.17) and because there is a glibc
   // wrapper.
   T_ (ii == p.len);  // next instruction now one past the end of the buffer
   Z_ (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p));
   DEBUG("note: see FAQ to disassemble the above")

   // Test filter with mknodat(2) on a sentinel file descriptor. If the kernel
   // actually executes the call, it will fail with EBADF due to the fake file
   // descriptor. The filter will instead do a successful no-op. See #1771.
   //
   // Other rejected options include:
   //
   //   1. Anything other than a no-op if the kernel executes it, even if this
   //      process is privileged for some reason, because we don’t want to
   //      make a mess if the filter doesn’t work.
   //
   //   2. Syscalls an application is unlikely to use and that are unlikely to
   //      grow stateful emulation, e.g. kexec_load(2), run afoul of common
   //      allow/deny-lists (see #1955).
   //
   //   3. Passing a NULL path to mknod(2) gives a compiler warning.
   Zf (mknodat(FD_TEST_NOOP, ".", S_IFCHR | 0600, makedev(1, 3)),
       "seccomp root emulation failed (is your architecture supported?)");
}
#endif

/* Wait for semaphore sem for up to timeout seconds. If timeout or an error,
   exit unsuccessfully. */
void sem_timedwait_relative(sem_t *sem, int timeout)
{
   struct timespec deadline;

   // sem_timedwait() requires a deadline rather than a timeout.
   Z_ (clock_gettime(CLOCK_REALTIME, &deadline));
   deadline.tv_sec += timeout;

   if (sem_timedwait(sem, &deadline)) {
      Ze (errno == ETIMEDOUT, "timeout waiting for join lock");
      Tf (0, "failure waiting for join lock");
   }
}

/* Activate the desired isolation namespaces. */
void setup_namespaces(const struct container *c, uid_t uid_out, uid_t uid_in,
                      gid_t gid_out, gid_t gid_in) {
   int fd;

   LOG_IDS;
   Zf (unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET), "can't init user+mount namespaces");
   LOG_IDS;

   /* Write UID map. What we are allowed to put here is quite limited. Because
      we do not have CAP_SETUID in the *parent* user namespace, we can map
      exactly one UID: an arbitrary container UID to our EUID in the parent
      namespace.

      This is sufficient to change our UID within the container; no setuid(2)
      or similar required. This is because the EUID of the process in the
      parent namespace is unchanged, so the kernel uses our new 1-to-1 map to
      convert that EUID into the container UID for most (maybe all)
      purposes. */
   T_ (-1 != (fd = open("/proc/self/uid_map", O_WRONLY)));
   T_ (1 <= dprintf(fd, "%d %d 1\n", uid_in, uid_out));
   Z_ (close(fd));
   LOG_IDS;

   T_ (-1 != (fd = open("/proc/self/setgroups", O_WRONLY)));
   T_ (1 <= dprintf(fd, "deny\n"));
   Z_ (close(fd));
   T_ (-1 != (fd = open("/proc/self/gid_map", O_WRONLY)));
   T_ (1 <= dprintf(fd, "%d %d 1\n", gid_in, gid_out));
   Z_ (close(fd));
   LOG_IDS;
}

/* Build /etc/passwd and /etc/group files and bind-mount them into newroot.

   /etc/passwd contains root, nobody, and an entry for the container UID,
   i.e., three entries, or two if the container UID is 0 or 65534. We copy the
   host's user data for the container UID, if that exists, and use dummy data
   otherwise (see issue #649). /etc/group works similarly: root, nogroup, and
   an entry for the container GID.

   We build new files to capture the relevant host username and group name
   mappings regardless of where they come from. We used to simply bind-mount
   the host's /etc/passwd and /etc/group, but this fails for LDAP at least;
   see issue #212. After bind-mounting, we remove the files from the host;
   they persist inside the container and then disappear completely when the
   container exits. */
void setup_passwd(const struct container *c) {
   int fd;
   char *path;
   struct group *g;
   struct passwd *p;

   // /etc/passwd
   T_ (path = cat(host_tmp, "/run_passwd.XXXXXX"));
   T_ (-1 != (fd = mkstemp(path))); // mkstemp(3) writes path
   if (c->uid != 0)
      T_ (1 <= dprintf(fd, "root:x:0:0:root:/root:/bin/sh\n"));
   if (c->uid != 65534)
      T_ (1 <= dprintf(fd, "nobody:x:65534:65534:nobody:/:/bin/false\n"));
   errno = 0;
   p = getpwuid(c->uid);
   if (p) {
      T_ (1 <= dprintf(fd, "%s:x:%u:%u:%s:/:/bin/sh\n", p->pw_name,
                       c->uid, c->gid, p->pw_gecos));
   } else {
      if (errno) {
         Tf (0, "getpwuid(3) failed");
      } else {
         VERBOSE("UID %d not found; using dummy info", c->uid);
         T_ (1 <= dprintf(fd, "%s:x:%u:%u:%s:/:/bin/sh\n", "clearly",
                          c->uid, c->gid, "Clearly"));
      }
   }
   Z_ (close(fd));
   bind_mount(path, "/etc/passwd", BD_REQUIRED, c->newroot, 0, NULL);
   Z_ (unlink(path));

   // /etc/group
   T_ (path = cat(host_tmp, "/run_group.XXXXXX"));
      T_ (-1 != (fd = mkstemp(path)));
   if (c->gid != 0)
      T_ (1 <= dprintf(fd, "root:x:0:\n"));
   if (c->gid != 65534)
      T_ (1 <= dprintf(fd, "nogroup:x:65534:\n"));
   errno = 0;
   g = getgrgid(c->gid);
   if (g) {
      T_ (1 <= dprintf(fd, "%s:x:%u:\n", g->gr_name, c->gid));
   } else {
      if (errno) {
         Tf (0, "getgrgid(3) failed");
      } else {
         VERBOSE("GID %d not found; using dummy info", c->gid);
         T_ (1 <= dprintf(fd, "%s:x:%u:\n", "clearlygroup", c->gid));
      }
   }
      Z_ (close(fd));
   bind_mount(path, "/etc/group", BD_REQUIRED, c->newroot, 0, NULL);
   Z_ (unlink(path));
}

/* Mount a tmpfs at the given path. */
void tmpfs_mount(const char *dst, const char *newroot, const char *data) {
   char *dst_full = cat(newroot, dst);

   Zf (mount(NULL, dst_full, "tmpfs", 0, data),
       "can't mount tmpfs at %s", dst_full);
}

/* Try to pull an image from a remote registry. Returns true if successful,
   false otherwise. */
bool pull_image(const char *ref, const char *storage_dir) {
   char *image_cmd;
   char *storage_arg = NULL;
   char *argv[8];
   int argc = 0;
   pid_t pid;
   int status;

   // Check if this looks like an image reference (contains ':' or '/')
   bool looks_like_image = (strchr(ref, ':') != NULL || strchr(ref, '/') != NULL);
   if (!looks_like_image) {
      return false;
   }

   // Log that we're attempting to pull the image
   INFO("Unable to find image '%s' locally", ref);

   // Build the command: clearly image pull <ref>
   // First, find the image command
   T_ (1 <= asprintf(&image_cmd, "%s/image", LIBEXECDIR));

   // Build argv array
   argv[argc++] = image_cmd;
   argv[argc++] = "pull";

   // Add storage directory if specified
   if (storage_dir != NULL && strcmp(storage_dir, "/var/tmp/$USER.clearly") != 0) {
      T_ (1 <= asprintf(&storage_arg, "--storage=%s", storage_dir));
      argv[argc++] = storage_arg;
   }

   argv[argc++] = (char *)ref;
   argv[argc] = NULL;

   pid = fork();
   if (pid == -1) {
      WARNING("can't fork to pull image: %s", ref);
      free(image_cmd);
      if (storage_arg) free(storage_arg);
      return false;
   }

   if (pid == 0) {
      execvp(image_cmd, argv);
      // If we get here, execvp failed
      ERROR(errno, "can't exec clearly image pull: %s", image_cmd);
      exit(EXIT_FAILURE);
   }

   if (waitpid(pid, &status, 0) == -1) {
      WARNING("can't wait for image pull process");
      free(image_cmd);
      if (storage_arg) free(storage_arg);
      return false;
   }

   free(image_cmd);
   if (storage_arg) free(storage_arg);

   if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      return true;
   } else {
      return false;
   }
}

/* Build the cgroup path and set the cgroup limits.

   cgroup_path: /sys/fs/cgroup/clearly/<pid>
   cgroup_pids_max: /sys/fs/cgroup/clearly/<pid>/pids.max
   cgroup_cpu_weight: /sys/fs/cgroup/clearly/<pid>/cpu.weight
   cgroup_memory_max: /sys/fs/cgroup/clearly/<pid>/memory.max
   cgroup_cpu_max: /sys/fs/cgroup/clearly/<pid>/cpu.max
*/
void cgroup_init(const struct container *c)
{
   int fd;
   pid_t pid = getpid();
   T_ (1 <= asprintf(&cgroup_path, "/sys/fs/cgroup/clearly/%d", pid));
   Zf(mkdir(cgroup_path, 0755), "can't create cgroup directory: %s", cgroup_path);
   if (c->cgroup_pids_max > 0) {
      char *pids_max_path = cat(cgroup_path, "/pids.max");
      T_ (-1 != (fd = open(pids_max_path, O_WRONLY)));
      T_ (1 <= dprintf(fd, "%ld", c->cgroup_pids_max));
      Z_ (close(fd));
      free(pids_max_path);
   }
   if (c->cgroup_cpu_weight) {
      char *cpu_weight_path = cat(cgroup_path, "/cpu.weight");
      T_ (-1 != (fd = open(cpu_weight_path, O_WRONLY)));
      T_ (1 <= dprintf(fd, "%s", c->cgroup_cpu_weight));
      Z_ (close(fd));
      free(cpu_weight_path);
   }
   if (c->cgroup_memory_max) {
      char *memory_max_path = cat(cgroup_path, "/memory.max");
      T_ (-1 != (fd = open(memory_max_path, O_WRONLY)));
      T_ (1 <= dprintf(fd, "%s", c->cgroup_memory_max));
      Z_ (close(fd));
      free(memory_max_path);
   }
   if (c->cgroup_cpu_max) {
      char *cpu_max_path = cat(cgroup_path, "/cpu.max");
      char *end;
      float cpus = strtof(c->cgroup_cpu_max, &end);
      Tf(end != c->cgroup_cpu_max, "invalid --cpus value");
      long quota = (long)(cpus * 100000);
      T_ (-1 != (fd = open(cpu_max_path, O_WRONLY)));
      T_ (1 <= dprintf(fd, "%ld 100000", quota));
      Z_ (close(fd));
      free(cpu_max_path);
   }
   char *procs_path = cat(cgroup_path, "/cgroup.procs");
   T_ (-1 != (fd = open(procs_path, O_WRONLY)));
   T_ (1 <= dprintf(fd, "%d", pid));
   Z_ (close(fd));
   free(procs_path);
}

/* Remove the cgroup path. */
void cgroup_cleanup(void)
{
   if (cgroup_path) {
      rmdir(cgroup_path);
      free(cgroup_path);
   }
}