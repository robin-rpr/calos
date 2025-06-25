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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <slirp/libslirp.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/addr.h>
#include <libnl3/netlink/route/route.h>
#include "misc.h"
#include "core.h"
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

struct pollfd_data {
    struct pollfd *fds;
    int nfds;
    int size;
};

/* Opaque data structure for libslirp callbacks. */
struct slirp_data {
    struct pollfd_data pfd_data;
    int socket_fd; // Socket to communicate with child
};

/* Timer structure for libslirp */
typedef struct {
    SlirpTimerCb cb;
    void *cb_opaque;
    // Monotonic time in nanoseconds when timer expires
    int64_t expire_time;
} MySlirpTimer;

/* Timer storage array for libslirp */
static MySlirpTimer **slirp_timers = NULL;
static int num_slirp_timers = 0;
static int slirp_timers_capacity = 0;

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
void parse_port_map(const char* map_str, int* host_port, int* guest_port);
int64_t clock_get_ns_cb(void *opaque);
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

/** Helpers **/

/* Send a file descriptor over a Unix socket. */
static void send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    struct iovec iov;
    char dummy = '*';

    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    Zf(sendmsg(sock, &msg, 0) == -1, "Failed to send file descriptor");
}

/* Receive a file descriptor over a Unix socket. */
static int recv_fd(int sock) {
    struct msghdr msg = {0};
    char cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    struct iovec iov;
    char dummy;
    int fd;

    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    Zf(recvmsg(sock, &msg, 0) == -1, "Failed to receive file descriptor");

    cmsg = CMSG_FIRSTHDR(&msg);
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

    return fd;
}

/** Callbacks **/

/* Callback for adding a file descriptor to the poll list. */
int add_poll_cb(int fd, int events, void *opaque) {
    struct slirp_data *sd = opaque;
    struct pollfd_data *d = &sd->pfd_data;

    // Check if the fd already exists in the list and update its events
    for (int i = 0; i < d->nfds; i++) {
        if (d->fds[i].fd == fd) {
            d->fds[i].events = events; // Update events
            return i; // Return its index
        }
    }

    // If not found, add it as a new fd
    if (d->nfds >= d->size) {
        d->size = d->size == 0 ? 8 : d->size * 2;
        d->fds = realloc(d->fds, d->size * sizeof(struct pollfd));
        Tf(d->fds != NULL, "Failed to reallocate pollfds");
    }
    d->fds[d->nfds].fd = fd;
    d->fds[d->nfds].events = events;
    d->nfds++;
    return d->nfds - 1;
}

/* Callback for getting the revents of a file descriptor. */
int get_revents_cb(int idx, void *opaque) {
    struct slirp_data *sd = opaque;
    struct pollfd_data *d = &sd->pfd_data;
    Tf(idx < d->nfds, "Poll index out of bounds");
    return d->fds[idx].revents;
}

/* Send a packet to the guest via the socket pair. */
static ssize_t send_packet_cb(const void *buf, size_t len, void *opaque)
{
   struct slirp_data *sd = opaque;
   uint32_t plen = len;

   // Frame the packet with its length to handle SOCK_STREAM.
   if (write(sd->socket_fd, &plen, sizeof(plen)) != sizeof(plen)) {
        perror("write packet length");
        return -1;
   }

   ssize_t written = write(sd->socket_fd, buf, len);
   return written;
}

/* Callback for handling errors from the guest. */
static void guest_error_cb(const char *msg, void *opaque) {
   fprintf(stderr, "slirp guest error: %s\n", msg);
}

/* Callback for creating a new timer. */
static void *timer_new_cb(SlirpTimerCb cb, void *cb_opaque, void *opaque) {
    VERBOSE("timer_new_cb: New timer created");
    MySlirpTimer *t = malloc(sizeof(MySlirpTimer));
    Tf(t != NULL, "Failed to allocate timer");
    t->cb = cb;
    t->cb_opaque = cb_opaque;
    t->expire_time = -1; // Not set yet, will be set by timer_mod_cb

    if (num_slirp_timers >= slirp_timers_capacity) {
        slirp_timers_capacity = slirp_timers_capacity == 0 ? 4 : slirp_timers_capacity * 2;
        slirp_timers = realloc(slirp_timers, slirp_timers_capacity * sizeof(MySlirpTimer*));
        Tf(slirp_timers != NULL, "Failed to reallocate slirp_timers array");
    }
    slirp_timers[num_slirp_timers++] = t;
    return t;
}

/* Callback for freeing a timer. */
static void timer_free_cb(void *timer, void *opaque) {
    VERBOSE("timer_free_cb: Timer freed");
    MySlirpTimer *t = (MySlirpTimer *)timer;
    for (int i = 0; i < num_slirp_timers; i++) {
        if (slirp_timers[i] == t) {
            // Found it, remove by shifting elements
            free(slirp_timers[i]); // Free the timer struct itself
            for (int j = i; j < num_slirp_timers - 1; j++) {
                slirp_timers[j] = slirp_timers[j+1];
            }
            num_slirp_timers--;
            return;
        }
    }
}

/* Callback for modifying a timer. */
static void timer_mod_cb(void *timer, int64_t expire_time, void *opaque) {
    MySlirpTimer *t = timer;
    VERBOSE("timer_mod_cb: Timer modified to expire at %lld ns", (long long)expire_time);
    t->expire_time = expire_time;
    // TODO: In a production timer implementation using timerfd(2), this
    // callback would update the timer file descriptor with the new
    // expiration time. The current array-based implementation maintains
    // timers in insertion order without sorting for simplicity.
}

/* Callback for registering a file descriptor. */
static void register_poll_fd_cb(int fd, void *opaque) {
    struct slirp_data *sd = opaque;
    VERBOSE("register_poll_fd_cb: Registering fd %d", fd);

    // This callback from libslirp just says "watch this FD".
    // The events will be filled by slirp_pollfds_fill later.
    // We need to ensure it's in our list. add_poll_cb can handle this.
    add_poll_cb(fd, 0, sd);
}

/* Callback for unregistering a file descriptor. */
static void unregister_poll_fd_cb(int fd, void *opaque) {
    struct slirp_data *sd = opaque;
    struct pollfd_data *d = &sd->pfd_data;
    VERBOSE("unregister_poll_fd_cb: Unregistering fd %d", fd);

    // Remove the file descriptor from the pollfd_data structure
    // This is a linear search and remove; for high performance, a different
    // data structure (like a hash map from fd to index) would be better.
    for (int i = 0; i < d->nfds; i++) {
        if (d->fds[i].fd == fd) {
            // Found it, shift elements down
            for (int j = i; j < d->nfds - 1; j++) {
                d->fds[j] = d->fds[j+1];
            }
            d->nfds--; // Reduce count
            // No reallocating here to avoid thrashing for small changes.
            // A periodic compaction might be beneficial if list shrinks a lot.
            VERBOSE("unregister_poll_fd_cb: Removed fd %d", fd);
            return;
        }
    }
    VERBOSE("unregister_poll_fd_cb: FD %d not found in tracked pollfds for unregistration.", fd);
}

/* Callback for notifying Slirp of internal events. */
static void notify_cb(void *opaque) {
    // This callback indicates that Slirp has internal state changes
    // and might need to be called again soon, even if no FDs are ready.
    VERBOSE("notify_cb: Slirp signalled internal event.");
}

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
                 unsigned long flags, const char * scratch)
{
   for (int i = 0; binds[i].src != NULL; i++)
      bind_mount(binds[i].src, binds[i].dst, binds[i].dep,
                 newroot, flags, scratch);
}

/* Set up new namespaces or join existing namespaces. */
void containerize(struct container *c)
{
    uid_t host_uid = geteuid();
    gid_t host_gid = getegid();
    int sp[2];

    Zf(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1, "failed to create socketpair");

    pid_t child_pid = fork();
    Zf(child_pid == -1, "failed to fork");

    /* Network configuration */
    struct in_addr vnetwork  = { .s_addr = inet_addr("172.17.0.0") };
    struct in_addr vnetmask  = { .s_addr = inet_addr("255.255.0.0") }; // /16
    struct in_addr vhost     = { .s_addr = inet_addr("172.17.0.1") };  // Gateway
    struct in_addr vguest    = { .s_addr = inet_addr("172.17.0.3") };  // Guest
    const int vcidr          = __builtin_popcount(ntohl(vnetmask.s_addr));
    struct in_addr no_addr   = {0};
    struct in6_addr no_addr6 = {0};

    if (child_pid > 0) {
        /* Parent Process */
        close(sp[1]); // Close child's end of socket pair

        char tap_name[IFNAMSIZ];
        int tap_fd = open("/dev/net/tun", O_RDWR);
        Tf(tap_fd >= 0, "Failed to open /dev/net/tun");

        struct ifreq ifr = {0};
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name, "tap0", IFNAMSIZ);

        Zf(ioctl(tap_fd, TUNSETIFF, (void *)&ifr) == -1,
           "Failed to create TAP device via ioctl(TUNSETIFF)");
        strncpy(tap_name, ifr.ifr_name, IFNAMSIZ);
        VERBOSE("TAP device '%s' created", tap_name);

        char ready_buf;
        Zf(read(sp[0], &ready_buf, 1) != 1 || ready_buf != 'R',
           "failed to receive ready signal from child");
        VERBOSE("parent received ready signal from child");

        // Move TAP into child's netns using libnl
        struct nl_sock *sock = nl_socket_alloc();
        Tf(sock != NULL, "failed to allocate netlink socket");
        Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

        struct rtnl_link *link;
        Zf(rtnl_link_get_kernel(sock, 0, tap_name, &link) < 0, "failed to get link %s", tap_name);
        int if_index = rtnl_link_get_ifindex(link);
        rtnl_link_put(link);

        struct rtnl_link *link_change = rtnl_link_alloc();
        Tf(link_change != NULL, "failed to allocate link for netns change");
        rtnl_link_set_ifindex(link_change, if_index);
        rtnl_link_set_ns_pid(link_change, child_pid);
        Zf(rtnl_link_add(sock, link_change, NLM_F_ACK) < 0, "failed to move link %s to child netns", tap_name);
        rtnl_link_put(link_change);
        nl_socket_free(sock);

        // Send the TAP device name and file descriptor to the child
        write(sp[0], tap_name, IFNAMSIZ);
        send_fd(sp[0], tap_fd);
        // Parent no longer needs this tap_fd
        close(tap_fd);

        struct slirp_data s_data = { .socket_fd = sp[0] };
        struct SlirpCb slirp_callbacks = {
           .send_packet = send_packet_cb,
           .guest_error = guest_error_cb,
           .clock_get_ns = clock_get_ns_cb,
           .timer_new = timer_new_cb,
           .timer_free = timer_free_cb,
           .timer_mod = timer_mod_cb,
           .register_poll_fd = register_poll_fd_cb,
           .unregister_poll_fd = unregister_poll_fd_cb,
           .notify = notify_cb,
        };

        const SlirpConfig slirp_cfg = {
            .version = SLIRP_CONFIG_VERSION_MAX,
            .restricted = false,
            .in_enabled = true,
            .vnetwork = vnetwork,
            .vnetmask = vnetmask,
            .vhost = vhost,
            .in6_enabled = false,
            .vnameserver = vhost,
            .vprefix_addr6 = no_addr6,
            .vprefix_len = 0,
            .vhost6 = no_addr6,
            .vhostname = NULL,
            .tftp_server_name = NULL,
            .tftp_path = NULL,
            .bootfile = NULL,
            .vdhcp_start = no_addr,
            .vnameserver6 = no_addr6,
            .vdnssearch = NULL,
            .vdomainname = NULL,
            .if_mtu = 0,
            .if_mru = 0,
            .disable_host_loopback = false,
            .enable_emu = false,
            .outbound_addr = NULL,
            .outbound_addr6 = NULL,
            .disable_dns = true,
        };

        Slirp *slirp = slirp_new(&slirp_cfg, &slirp_callbacks, &s_data);
        Tf(slirp != NULL, "slirp_new failed");

        // Add port forwarding rules
        for (int i = 0; c->port_map_strs[i] != NULL; i++) {
            int host_port, guest_port;
            parse_port_map(c->port_map_strs[i], &host_port, &guest_port);
            struct in_addr host_addr = { .s_addr = INADDR_ANY };
            slirp_add_hostfwd(slirp, false, host_addr, host_port, vguest, guest_port);
            VERBOSE("forwarding host port %d to guest port %d", host_port, guest_port);
        }

        // Add host entries to /etc/hosts
        for (int i = 0; c->host_map_strs[i] != NULL; i++) {
            char *hostname;
            struct in_addr ip_addr;
            parse_host_map(c->host_map_strs[i], &hostname, &ip_addr);

            char *hosts_path = cat(c->newroot, "/etc/hosts");
            FILE *hosts_file = fopen(hosts_path, "a");
            if (hosts_file && fprintf(hosts_file, "%s %s\n", inet_ntoa(ip_addr), hostname) > 0) {
                VERBOSE("adding host entry %s %s to /etc/hosts", inet_ntoa(ip_addr), hostname);
            } else {
                VERBOSE("failed to write to /etc/hosts: %s", hosts_path);
            }
            
            if (hosts_file) fclose(hosts_file);
            free(hosts_path);
            free(hostname);
        }
        
        int exited = 0;
        char slirp_buf[4096];
        while (!exited) {
            uint32_t timeout_ms = -1;
            // Reset nfds to 0 so slirp_pollfds_fill can rebuild the list
            s_data.pfd_data.nfds = 0;
            slirp_pollfds_fill(slirp, &timeout_ms, add_poll_cb, &s_data);

            // Dynamically resize the pollfd array if needed before adding sp[0]
            if (s_data.pfd_data.nfds >= s_data.pfd_data.size) {
                s_data.pfd_data.size = s_data.pfd_data.size == 0 ? 8 : s_data.pfd_data.size * 2;
                s_data.pfd_data.fds = realloc(s_data.pfd_data.fds, s_data.pfd_data.size * sizeof(struct pollfd));
                Tf(s_data.pfd_data.fds != NULL, "Failed to reallocate pollfds");
            }

            // Add our socket to the child to the list of polled fds
            s_data.pfd_data.fds[s_data.pfd_data.nfds].fd = sp[0];
            s_data.pfd_data.fds[s_data.pfd_data.nfds].events = POLLIN;
            s_data.pfd_data.nfds++;

            int ret = poll(s_data.pfd_data.fds, s_data.pfd_data.nfds, timeout_ms);

            // If poll() returns an error, break the loop
            if (ret < 0) {
                perror("parent poll");
                break;
            }

            // If poll() returns > 0, there are events to process
            if (ret > 0) {
                // *** THE ROBUST FIX ***
                // Iterate through ALL file descriptors poll was watching.
                for (int i = 0; i < s_data.pfd_data.nfds; i++) {
                    // Skip any FDs that had no events
                    if (s_data.pfd_data.fds[i].revents == 0) {
                        continue;
                    }

                    // Check if the event is on our socket to the child proxy
                    if (s_data.pfd_data.fds[i].fd == sp[0]) {
                        // Handle hangup/error events from the proxy
                        if (s_data.pfd_data.fds[i].revents & (POLLHUP | POLLERR)) {
                            VERBOSE("child proxy connection error/hangup.");
                            exited = 1;
                            break; // Exit the for loop
                        }
                        // Handle readable data FROM the child (the HTTP response)
                        if (s_data.pfd_data.fds[i].revents & POLLIN) {
                            uint32_t plen;
                            ssize_t len = read(sp[0], &plen, sizeof(plen));
                            if (len == sizeof(plen)) {
                                if (plen > sizeof(slirp_buf)) {
                                    FATAL(0, "slirp buffer too small for packet size %u", plen);
                                }
                                len = read(sp[0], slirp_buf, plen);
                                if (len > 0) {
                                    slirp_input(slirp, (const uint8_t *)slirp_buf, len);
                                }
                            }
                            if (len <= 0) {
                                VERBOSE("child proxy closed connection.");
                                exited = 1;
                                break; // Exit the for loop
                            }
                        }
                    }
                }
            }

            // After we've handled our specific socket, let slirp process its events.
            // It will use the same 'revents' fields from the poll() call.
            if (!exited) {
                slirp_pollfds_poll(slirp, ret == 0, get_revents_cb, &s_data);
            }

            // Check if the main child process (not the proxy) has exited
            int status;
            if (waitpid(child_pid, &status, WNOHANG) == child_pid) {
                VERBOSE("main child process exited.");
                exited = 1;
            }
        }

        // Cleanup timers
        for (int i = 0; i < num_slirp_timers; i++) {
            // Note: timer_free_cb actually frees the MySlirpTimer struct
            // We just need to free the array of pointers here
            free(slirp_timers[i]);
        }
        free(slirp_timers);
        slirp_timers = NULL;
        num_slirp_timers = 0;
        slirp_timers_capacity = 0;

        slirp_cleanup(slirp);
        free(s_data.pfd_data.fds);
        close(sp[0]);
        exit(0);

    } else {
        /* Child Process */
        close(sp[0]); // Close parent's end

        if (c->join_pid) {
            join_namespaces(c->join_pid);
            // NOTE: Networking is not handled for joined containers in this logic.
            return;
        }

        if (c->join)
            join_begin(c->join_tag);

        if (!c->join || join.winner_p) {
            setup_namespaces(c, host_uid, 0, host_gid, 0);
#ifdef HAVE_LIBSQUASHFUSE
            if (c->type == IMG_SQUASH)
                sq_fork(c);
#endif
            setup_namespaces(c, 0, c->container_uid, 0, c->container_gid);
            enter_udss(c);
        } else {
            join_namespaces(join.shared->winner_pid);
        }

        if (c->join)
            join_end(c->join_ct);

        // Add nameserver entries to /etc/resolv.conf
        FILE *resolv_conf = fopen("/etc/resolv.conf", "w");
        if (resolv_conf != NULL) {
            fprintf(resolv_conf, "nameserver 1.1.1.1\n");
            fclose(resolv_conf);
        }

        // Signal parent that we are in the correct namespaces and ready for the TAP device.
        Zf(write(sp[1], "R", 1) != 1, "child failed to send ready signal");

        // Receive TAP device info from parent
        char tap_name[IFNAMSIZ];
        Zf(read(sp[1], tap_name, IFNAMSIZ) <= 0, "child failed to receive tap name");
        int tap_fd = recv_fd(sp[1]);

        // Connect to netlink route socket
        struct nl_sock *sock = nl_socket_alloc();
        Tf(sock != NULL, "failed to allocate netlink socket");
        Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

        // Configure tap0 interface
        struct rtnl_link *link;
        Zf(rtnl_link_get_kernel(sock, 0, tap_name, &link) < 0, "failed to get link %s", tap_name);
        int if_index = rtnl_link_get_ifindex(link);
        rtnl_link_put(link);

        struct rtnl_link *link_change = rtnl_link_alloc();
        rtnl_link_set_ifindex(link_change, if_index);
        rtnl_link_set_flags(link_change, IFF_UP);
        Zf(rtnl_link_add(sock, link_change, NLM_F_ACK) < 0, "failed to bring up link %s", tap_name);
        rtnl_link_put(link_change);

        struct rtnl_addr *local_addr = rtnl_addr_alloc();
        struct nl_addr *local_ip;
        char vguest_str[INET_ADDRSTRLEN + 4];
        inet_ntop(AF_INET, &vguest, vguest_str, sizeof(vguest_str));
        snprintf(vguest_str + strlen(vguest_str), sizeof(vguest_str) - strlen(vguest_str), "/%d", vcidr);
        Zf(nl_addr_parse(vguest_str, AF_INET, &local_ip) < 0, "failed to parse address");
        rtnl_addr_set_local(local_addr, local_ip);
        nl_addr_put(local_ip);
        rtnl_addr_set_ifindex(local_addr, if_index);
        Zf(rtnl_addr_add(sock, local_addr, 0) < 0, "failed to add address");
        rtnl_addr_put(local_addr);

        struct rtnl_route *route = rtnl_route_alloc();
        struct nl_addr *gw_addr;
        char gw_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &vhost, gw_str, sizeof(gw_str));
        Zf(nl_addr_parse(gw_str, AF_INET, &gw_addr) < 0, "failed to parse gateway");
        struct rtnl_nexthop *nh = rtnl_route_nh_alloc();
        rtnl_route_nh_set_ifindex(nh, if_index);
        rtnl_route_nh_set_gateway(nh, gw_addr);
        rtnl_route_add_nexthop(route, nh);
        nl_addr_put(gw_addr);

        // Configure lo interface
        struct rtnl_link *lo_link;
        Zf(rtnl_link_get_kernel(sock, 0, "lo", &lo_link) < 0, "failed to get loopback link 'lo'");
        int lo_if_index = rtnl_link_get_ifindex(lo_link);
        rtnl_link_put(lo_link);

        struct rtnl_link *lo_link_change = rtnl_link_alloc();
        Tf(lo_link_change != NULL, "failed to allocate link for lo config");
        rtnl_link_set_ifindex(lo_link_change, lo_if_index);
        rtnl_link_set_flags(lo_link_change, IFF_UP);
        Zf(rtnl_link_add(sock, lo_link_change, NLM_F_ACK) < 0, "failed to bring up lo interface");
        rtnl_link_put(lo_link_change);

        // Configure default route
        struct nl_addr *dst_addr;
        Zf(nl_addr_parse("0.0.0.0/0", AF_INET, &dst_addr) < 0, "failed to parse route destination");
        rtnl_route_set_dst(route, dst_addr);
        nl_addr_put(dst_addr);

        Zf(rtnl_route_add(sock, route, 0) < 0, "failed to add route");
        rtnl_route_put(route);
        nl_socket_free(sock);

        // Fork to have a dedicated process for network proxying
        pid_t proxy_pid = fork();
        Zf(proxy_pid < 0, "failed to fork proxy process");

        if (proxy_pid == 0) {
            // Child becomes the proxy
            // Shuttling packets between TAP and parent
            struct pollfd fds[2];
            fds[0].fd = tap_fd;
            fds[0].events = POLLIN;
            fds[1].fd = sp[1];
            fds[1].events = POLLIN;
            char buf[4096];

            while (1) {
                int ret = poll(fds, 2, -1);
                if (ret <= 0) {
                    perror("proxy poll");
                    break;
                }
                if (fds[0].revents & POLLIN) {
                    // Data from TAP device
                    ssize_t len = read(tap_fd, buf, sizeof(buf));
                    if (len > 0) {
                        uint32_t plen = len;
                        write(sp[1], &plen, sizeof(plen)); // Send length
                        write(sp[1], buf, len);            // Send data
                    } else {
                        // TAP closed or error
                        break;
                    }
                }
                if (fds[1].revents & POLLIN) {
                    // Data from parent (slirp)
                    uint32_t plen;
                    ssize_t len = read(sp[1], &plen, sizeof(plen));
                    if (len == sizeof(plen)) {
                         if (plen > sizeof(buf)) {
                             // Should not happen
                             break;
                         }
                         len = read(sp[1], buf, plen);
                         if (len > 0) {
                             write(tap_fd, buf, len);
                         } else {
                             break;
                         }
                    } else {
                        // Parent closed socket or error
                        break;
                    }
                }
            }
            close(tap_fd);
            close(sp[1]);
            exit(0);
        }
        close(sp[1]);
        close(tap_fd);
    }
}

/* Enter the new root (UDSS). On entry, the namespaces are set up, and this
   does the mounting and filesystem setup.

   Note that pivot_root(2) requires a complex dance to work, i.e., to avoid
   multiple undocumented error conditions. This dance is explained in detail
   in bin/checkns.c. */
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
   if (!c->private_passwd)
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

char *img_name2path(const char *name, const char *storage_dir)
   {
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

/* Helper function to parse "HOST_PORT:GUEST_PORT" string. */
void parse_port_map(const char* map_str, int* host_port, int* guest_port) {
    char* str = strdup(map_str);
    char* colon = strchr(str, ':');
    Tf(colon != NULL, "Invalid port map format. Expected HOST_PORT:GUEST_PORT");
    *colon = '\0';
    *host_port = atoi(str);
    *guest_port = atoi(colon + 1);
    free(str);
}

/* Helper function to get the current time in nanoseconds. */
int64_t clock_get_ns_cb(void *opaque) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Begin coordinated section of namespace joining. */
void join_begin(const char *join_tag)
{
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
void join_end(int join_ct)
{
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
void join_namespace(pid_t pid, const char *ns)
{
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
void join_namespaces(pid_t pid)
{
   VERBOSE("joining namespaces of pid %d", pid);
   join_namespace(pid, "user");
   join_namespace(pid, "mnt");
}

/* Replace the current process with user command and arguments. */
void run_user_command(char *argv[], const char *initial_dir)
{
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
void seccomp_install(void)
{
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
                      gid_t gid_out, gid_t gid_in)
{
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
void setup_passwd(const struct container *c)
{
   int fd;
   char *path;
   struct group *g;
   struct passwd *p;

   // /etc/passwd
   T_ (path = cat(host_tmp, "/run_passwd.XXXXXX"));
   T_ (-1 != (fd = mkstemp(path)));  // mkstemp(3) writes path
   if (c->container_uid != 0)
      T_ (1 <= dprintf(fd, "root:x:0:0:root:/root:/bin/sh\n"));
   if (c->container_uid != 65534)
      T_ (1 <= dprintf(fd, "nobody:x:65534:65534:nobody:/:/bin/false\n"));
   errno = 0;
   p = getpwuid(c->container_uid);
   if (p) {
      T_ (1 <= dprintf(fd, "%s:x:%u:%u:%s:/:/bin/sh\n", p->pw_name,
                       c->container_uid, c->container_gid, p->pw_gecos));
   } else {
      if (errno) {
         Tf (0, "getpwuid(3) failed");
      } else {
         VERBOSE("UID %d not found; using dummy info", c->container_uid);
         T_ (1 <= dprintf(fd, "%s:x:%u:%u:%s:/:/bin/sh\n", "clearly",
                          c->container_uid, c->container_gid, "Clearly"));
      }
   }
   Z_ (close(fd));
   bind_mount(path, "/etc/passwd", BD_REQUIRED, c->newroot, 0, NULL);
   Z_ (unlink(path));

   // /etc/group
   T_ (path = cat(host_tmp, "/run_group.XXXXXX"));
      T_ (-1 != (fd = mkstemp(path)));
   if (c->container_gid != 0)
      T_ (1 <= dprintf(fd, "root:x:0:\n"));
   if (c->container_gid != 65534)
      T_ (1 <= dprintf(fd, "nogroup:x:65534:\n"));
   errno = 0;
   g = getgrgid(c->container_gid);
   if (g) {
      T_ (1 <= dprintf(fd, "%s:x:%u:\n", g->gr_name, c->container_gid));
   } else {
      if (errno) {
         Tf (0, "getgrgid(3) failed");
      } else {
         VERBOSE("GID %d not found; using dummy info", c->container_gid);
         T_ (1 <= dprintf(fd, "%s:x:%u:\n", "clearlygroup", c->container_gid));
      }
   }
      Z_ (close(fd));
   bind_mount(path, "/etc/group", BD_REQUIRED, c->newroot, 0, NULL);
   Z_ (unlink(path));
}

/* Mount a tmpfs at the given path. */
void tmpfs_mount(const char *dst, const char *newroot, const char *data)
{
   char *dst_full = cat(newroot, dst);

   Zf (mount(NULL, dst_full, "tmpfs", 0, data),
       "can't mount tmpfs at %s", dst_full);
}

/* Try to pull an image from a remote registry. Returns true if successful,
   false otherwise. */
bool pull_image(const char *ref, const char *storage_dir)
{
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