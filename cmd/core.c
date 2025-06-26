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
#include <linux/netfilter/nf_tables.h>
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
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/addr.h>
#include <libnl3/netlink/route/route.h>
#include <libnl3/netlink/route/link/veth.h>
#include <libnl3/netlink/route/link/bridge.h>
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

/* Linux Kernel constants for netfilter.
   partially sourced from <linux/netfilter/nf_tables.h> */
#define NFPROTO_IPV4 2
#define NF_ACCEPT 1
#define NF_INET_POST_ROUTING 4
#define NFT_PRIORITY_NAT_POSTROUTING -100
#define NFTNL_EXPR_META_LEN 3
#define NFTNL_EXPR_META_DEV 4
#define NFT_POLICY_ACCEPT 0

#ifndef __KERNEL__
/* IP Cache bits. */
/* Src IP address. */
#define NFC_IP_SRC		0x0001
/* Dest IP address. */
#define NFC_IP_DST		0x0002
/* Input device. */
#define NFC_IP_IF_IN		0x0004
/* Output device. */
#define NFC_IP_IF_OUT		0x0008
/* TOS. */
#define NFC_IP_TOS		0x0010
/* Protocol. */
#define NFC_IP_PROTO		0x0020
/* IP options. */
#define NFC_IP_OPTIONS		0x0040
/* Frag & flags. */
#define NFC_IP_FRAG		0x0080

/* Per-protocol information: only matters if proto match. */
/* TCP flags. */
#define NFC_IP_TCPFLAGS		0x0100
/* Source port. */
#define NFC_IP_SRC_PT		0x0200
/* Dest port. */
#define NFC_IP_DST_PT		0x0400
/* Something else about the proto */
#define NFC_IP_PROTO_UNKNOWN	0x2000

/* IP Hooks */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5
#endif /* ! __KERNEL__ */



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

/* Create and configure a network bridge if it doesn't already exist. */
static void setup_bridge(const char *bridge_name, const struct in_addr *ip, int cidr) {
    struct nl_sock *sock = nl_socket_alloc();
    Tf(sock != NULL, "failed to allocate netlink socket");
    Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

    // Check if bridge exists by trying to get it.
    if (rtnl_link_get_kernel(sock, 0, bridge_name, NULL) == 0) {
        VERBOSE("bridge '%s' already exists", bridge_name);
        nl_socket_free(sock);
        return;
    }

    VERBOSE("bridge '%s' not found, creating...", bridge_name);
    // Create the bridge link.
    struct rtnl_link *bridge = rtnl_link_bridge_alloc();
    Tf(bridge != NULL, "failed to allocate bridge link");
    rtnl_link_set_name(bridge, bridge_name);
    rtnl_link_set_type(bridge, "bridge");
    rtnl_link_set_flags(bridge, IFF_UP);
    Zf(rtnl_link_add(sock, bridge, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK) < 0,
       "failed to create bridge '%s'", bridge_name);
    rtnl_link_put(bridge);

    // Get the link again to configure it.
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, bridge_name, &link) < 0,
       "failed to get new bridge link '%s'", bridge_name);
    int if_index = rtnl_link_get_ifindex(link);

    // Set its IP address.
    struct rtnl_addr *addr = rtnl_addr_alloc();
    struct nl_addr *local_ip;
    char ip_str[INET_ADDRSTRLEN + 4];
    snprintf(ip_str, sizeof(ip_str), "%s/%d", inet_ntoa(*ip), cidr);
    Zf(nl_addr_parse(ip_str, AF_INET, &local_ip) < 0, "failed to parse address %s", ip_str);
    rtnl_addr_set_local(addr, local_ip);
    nl_addr_put(local_ip);
    rtnl_addr_set_ifindex(addr, if_index);
    Zf(rtnl_addr_add(sock, addr, 0) < 0, "failed to add address to bridge '%s'", bridge_name);
    rtnl_addr_put(addr);

    nl_socket_free(sock);
    VERBOSE("bridge '%s' created and configured", bridge_name);
}

/* Create a veth pair. */
static void create_veth_pair(struct nl_sock *sock, const char *host_name, const char *peer_name) {
    struct rtnl_link *veth = rtnl_link_veth_alloc();
    Tf(veth != NULL, "failed to allocate veth link");

    rtnl_link_set_name(veth, host_name);

    struct rtnl_link *peer = rtnl_link_veth_get_peer(veth);
    rtnl_link_set_name(peer, peer_name);

    Zf(rtnl_link_add(sock, veth, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK) < 0,
       "failed to create veth pair ('%s', '%s')", host_name, peer_name);

    rtnl_link_put(veth);
    VERBOSE("veth pair ('%s', '%s') created", host_name, peer_name);
}

/* Attach a link to a bridge and bring it up. */
static void attach_to_bridge_and_up(struct nl_sock *sock, const char *link_name, const char *bridge_name) {
    struct rtnl_link *link, *bridge;
    Zf(rtnl_link_get_kernel(sock, 0, link_name, &link) < 0, "failed to get link '%s'", link_name);
    Zf(rtnl_link_get_kernel(sock, 0, bridge_name, &bridge) < 0, "failed to get bridge '%s'", bridge_name);

   // Clone the link so we can modify and apply it
   struct rtnl_link *link_change = rtnl_link_alloc();
   Zf(link_change == NULL, "failed to allocate link");

   rtnl_link_set_ifindex(link_change, rtnl_link_get_ifindex(link));
   rtnl_link_set_master(link_change, rtnl_link_get_ifindex(bridge));
   rtnl_link_set_flags(link_change, IFF_UP);

   Zf(rtnl_link_change(sock, link, link_change, 0) < 0, "failed to attach and bring up '%s'", link_name);

   rtnl_link_put(link_change);
   rtnl_link_put(link);
   rtnl_link_put(bridge);
    VERBOSE("link '%s' attached to bridge '%s' and set up", link_name, bridge_name);
}

/* Move a network link to a different network namespace. */
static void move_link_to_ns(struct nl_sock *sock, const char *link_name, pid_t pid) {
    struct rtnl_link *link;
    Zf(rtnl_link_get_kernel(sock, 0, link_name, &link) < 0, "failed to get link '%s'", link_name);
    int if_index = rtnl_link_get_ifindex(link);
    Zf(if_index <= 0, "invalid ifindex for link '%s'", link_name);

    // Clone the link so we can modify and apply it
    struct rtnl_link *link_change = rtnl_link_alloc();
    Tf(link_change != NULL, "failed to allocate link for netns change");
    rtnl_link_set_ifindex(link_change, if_index);
    rtnl_link_set_ns_pid(link_change, pid);
    Zf(rtnl_link_add(sock, link_change, NLM_F_ACK) < 0, "failed to move link '%s' to pid", link_name, pid);

    rtnl_link_put(link_change);
    rtnl_link_put(link);
    VERBOSE("link '%s' moved to network namespace of pid %d", link_name, pid);
}

/* Set up NAT rules for container outbound traffic. */
static int setup_nat_masquerade() {
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        return -1;
    }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        mnl_socket_close(nl);
        return -1;
    }

    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    uint32_t seq = time(NULL);

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);
    struct nlmsghdr *nlh;

    /*
     * OPERATION 1: Create the 'nat' table if it doesn't exist.
     */
    struct nftnl_table *table = nftnl_table_alloc();
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);
    nftnl_table_set_str(table, NFTNL_TABLE_NAME, "nat");
    nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_IPV4,
                                     NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_table_nlmsg_build_payload(nlh, table);
    nftnl_table_free(table);
    mnl_nlmsg_batch_next(batch);

    /*
     * OPERATION 2: Create the 'postrouting' chain for NAT.
     */
    struct nftnl_chain *chain = nftnl_chain_alloc();
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, "nat");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, "postrouting");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "nat");
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_IP_POST_ROUTING);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 100); // SNAT priority
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_POLICY, NF_ACCEPT);

    nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                      NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
                                      NLM_F_CREATE | NLM_F_ACK, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    nftnl_chain_free(chain);
    mnl_nlmsg_batch_next(batch);

    /*
     * OPERATION 3: Add the masquerade rule for the container subnet.
     */
    struct nftnl_rule *rule = nftnl_rule_alloc();
    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "postrouting");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    struct nftnl_expr *match;

   match = nftnl_expr_alloc("payload");
   nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
   nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
   nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint32_t));
   nftnl_expr_set_u32(match, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
   nftnl_rule_add_expr(rule, match);

   uint32_t mask = htonl(0xffff0000); // /16
   match = nftnl_expr_alloc("bitwise");
   nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_SREG, NFT_REG_1);
   nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_DREG, NFT_REG_1);
   nftnl_expr_set_u32(match, NFTNL_EXPR_BITWISE_LEN, sizeof(uint32_t));
   nftnl_expr_set_data(match, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
   uint32_t zero = 0;
   nftnl_expr_set_data(match, NFTNL_EXPR_BITWISE_XOR, &zero, sizeof(zero));
   nftnl_rule_add_expr(rule, match);

   struct in_addr subnet;
   inet_pton(AF_INET, "172.19.0.0", &subnet);

   match = nftnl_expr_alloc("cmp");
   nftnl_expr_set_u32(match, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
   nftnl_expr_set_u32(match, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
   nftnl_expr_set_data(match, NFTNL_EXPR_CMP_DATA, &subnet, sizeof(subnet));
   nftnl_rule_add_expr(rule, match);

    // Add the 'masquerade' action
    struct nftnl_expr *expr = nftnl_expr_alloc("masq");
    nftnl_rule_add_expr(rule, expr);

    nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWRULE, NFPROTO_IPV4,
                                     NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule);
    mnl_nlmsg_batch_next(batch);

    /* End the batch */
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

      size_t batch_size = mnl_nlmsg_batch_size(batch);
      struct nlmsghdr *nlh_dbg = mnl_nlmsg_batch_head(batch);
      char *end = (char *)nlh_dbg + batch_size;

      while ((char *)nlh_dbg < end) {
         printf("DEBUG: sending msg type=%u flags=0x%x len=%u seq=%u\n",
               nlh_dbg->nlmsg_type, nlh_dbg->nlmsg_flags,
               nlh_dbg->nlmsg_len, nlh_dbg->nlmsg_seq);
         nlh_dbg = (struct nlmsghdr *)((char *)nlh_dbg + NLMSG_ALIGN(nlh_dbg->nlmsg_len));
      }

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_sendto");
        mnl_socket_close(nl);
        return -1;
    }

    int ret;
    int error_found = 0;
    while (!error_found && (ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        int bytes_left = ret;
        struct nlmsghdr *nlh_recv = (struct nlmsghdr *)buf;

        for (; mnl_nlmsg_ok(nlh_recv, bytes_left); nlh_recv = mnl_nlmsg_next(nlh_recv, &bytes_left)) {
            if (nlh_recv->nlmsg_type == NLMSG_ERROR) {
               struct nlmsgerr *err_ptr = (struct nlmsgerr *)mnl_nlmsg_get_payload(nlh_recv);
               if (err_ptr->error != 0) {
                  fprintf(stderr, "Kernel transaction failed: %s (type=%u seq=%u)\n",
                           strerror(-err_ptr->error),
                           nlh_recv->nlmsg_type, nlh_recv->nlmsg_seq);
                  error_found = 1;
                  break;
               }
            }
        }
    }

    if (ret < 0) {
        perror("mnl_socket_recvfrom");
        mnl_socket_close(nl);
        return -1;
    }

    mnl_socket_close(nl);

    if (error_found) {
        // Error already printed above.
        return -1;
    }

    VERBOSE("nftables masquerade rule installed");
    return 0;
}

/* Enable IP forwarding. */
static void enable_ip_forwarding() {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    Zf(f == NULL, "failed to open ip_forward");
    Zf(fprintf(f, "1\n") < 0, "failed to write to ip_forward");
    fclose(f);
    VERBOSE("IP forwarding enabled");
}

/* Set up port forwarding from host to container. */
static void setup_port_forwarding(int host_port, int guest_port, const struct in_addr *guest_ip) {
    struct nftnl_rule *rule = nftnl_rule_alloc();
    Tf(rule != NULL, "Failed to alloc nftnl_rule for port forwarding");

    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "nat");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "prerouting");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);

    // Match TCP protocol by loading it from the IP header
    struct nftnl_expr *expr;
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "Failed to alloc payload expr for protocol");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, protocol));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint8_t));
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "Failed to alloc cmp expr for protocol");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, 1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_DATA, IPPROTO_TCP);
    nftnl_rule_add_expr(rule, expr);

    // Match destination port
    expr = nftnl_expr_alloc("payload");
    Tf(expr != NULL, "Failed to alloc payload expr for dport");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct tcphdr, th_dport));
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, sizeof(uint16_t));
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    Tf(expr != NULL, "Failed to alloc cmp expr for dport");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, 1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set_u16(expr, NFTNL_EXPR_CMP_DATA, htons(host_port));
    nftnl_rule_add_expr(rule, expr);

    // Perform DNAT using registers for compatibility
    expr = nftnl_expr_alloc("immediate");
    Tf(expr != NULL, "Failed to alloc immediate expr for DNAT addr");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_1);
    nftnl_expr_set_data(expr, NFTNL_EXPR_IMM_DATA, guest_ip, sizeof(*guest_ip));
    nftnl_rule_add_expr(rule, expr);

    uint16_t guest_port_be = htons(guest_port);
    expr = nftnl_expr_alloc("immediate");
    Tf(expr != NULL, "Failed to alloc immediate expr for DNAT port");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_2);
    nftnl_expr_set_data(expr, NFTNL_EXPR_IMM_DATA, &guest_port_be, sizeof(guest_port_be));
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("nat");
    Tf(expr != NULL, "Failed to alloc nat expr");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_TYPE, NFT_NAT_DNAT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_FAMILY, NFPROTO_IPV4);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_NAT_REG_PROTO_MIN, NFT_REG_2);
    nftnl_rule_add_expr(rule, expr);

    // Send rule to kernel
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    Tf(nl != NULL, "Failed to open netlink socket for port forward");
    Zf(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0, "mnl bind failed for port forward");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE,
                                                      NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK, 0);
    nftnl_rule_nlmsg_build_payload(nlh, rule);

    int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    Zf(ret < 0, "Failed to send port forward rule");

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    Zf(ret < 0, "Failed to receive ACK for port forward rule");

    nftnl_rule_free(rule);
    mnl_socket_close(nl);

    VERBOSE("nftables DNAT rule added for tcp host port %d -> %s:%d", host_port, inet_ntoa(*guest_ip), guest_port);
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
void containerize(struct container *c) {
    uid_t host_uid = geteuid();
    gid_t host_gid = getegid();
    int sync_pipe[2];

    /* Network configuration */
    const char *bridge_name = "clearly0";
    const char *veth_host_prefix = "veth-host";
    const char *veth_guest_name = "eth0"; // Final name in container
    char veth_peer_name[IFNAMSIZ]; // Temp name before renaming to eth0

    const int cidr = 16;
    char network_cidr[18];
    struct in_addr bridge_ip  = { .s_addr = inet_addr("172.19.0.1") };
    struct in_addr guest_ip   = { .s_addr = inet_addr("172.19.0.2") };
    snprintf(network_cidr, sizeof(network_cidr), "172.19.0.0/%d", cidr);


    // Use a pipe to synchronize parent and child. The child will write to the
    // pipe only after it has entered its new namespaces.
    Zf(socketpair(AF_UNIX, SOCK_STREAM, 0, sync_pipe) == -1, "failed to create sync socketpair");


    pid_t child_pid = fork();
    Zf(child_pid == -1, "failed to fork");

    if (child_pid > 0) {
        /* Parent Process */
        close(sync_pipe[1]); // Close unused write end

        // Set up host-side networking for the container.
        char veth_host_name[IFNAMSIZ];
        snprintf(veth_host_name, IFNAMSIZ, "%.*s%d", IFNAMSIZ - 11, veth_host_prefix, child_pid);
        snprintf(veth_peer_name, IFNAMSIZ, "veth-peer%05d", child_pid % 100000);
        
        // Ensure bridge exists and is configured.
        setup_bridge(bridge_name, &bridge_ip, cidr);

        // Set up NAT rules.
        setup_nat_masquerade(bridge_name, network_cidr);
        enable_ip_forwarding();
        
        // Create the veth pair.
        struct nl_sock *sock = nl_socket_alloc();
        Tf(sock != NULL, "failed to allocate netlink socket");
        Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");
        
        create_veth_pair(sock, veth_host_name, veth_peer_name);

        // Set a random MAC address for the container interface.
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        Tf(fd >= 0, "failed to create socket for ioctl");
        struct ifreq ifr = {0};
        unsigned char mac[6];
        mac[0] = 0x02; // locally administered unicast
        for (int i = 1; i < 6; i++) {
           mac[i] = rand() % 256;
        }
        strncpy(ifr.ifr_name, veth_peer_name, IFNAMSIZ);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
        Zf(ioctl(fd, SIOCSIFHWADDR, &ifr), "ioctl(SIOCSIFHWADDR) failed for %s", veth_peer_name);
        close(fd);
        VERBOSE("set MAC address for %s to %02x:%02x:%02x:%02x:%02x:%02x", veth_peer_name,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        
        // Attach host end of veth to bridge and bring it up.
        attach_to_bridge_and_up(sock, veth_host_name, bridge_name);

        // Wait for child to signal that it's in its new namespaces.
        char buf;
        Zf(read(sync_pipe[0], &buf, 1) != 1 || buf != 'S', "failed to sync with child");
        
        // Move peer end of veth into the container's network namespace FIRST.
        move_link_to_ns(sock, veth_peer_name, child_pid);

        // Signal the child that it can proceed.
        Zf(write(sync_pipe[0], "R", 1) != 1, "failed to signal child");
        close(sync_pipe[0]);
        VERBOSE("parent synced with child");
        
        nl_socket_free(sock);

        // Set up port forwarding rules.
        for (int i = 0; c->port_map_strs[i] != NULL; i++) {
            int host_port, guest_port;
            parse_port_map(c->port_map_strs[i], &host_port, &guest_port);
            setup_port_forwarding(host_port, guest_port, &guest_ip);
        }

        // Wait for child process to exit.
        int status;
        waitpid(child_pid, &status, 0);

        // Optional: cleanup network interfaces. For simplicity, we don't.
        exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);

    } else {
        /* Child Process */
        close(sync_pipe[0]); // Close unused read end

        if (c->join_pid) {
            join_namespaces(c->join_pid);
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

        // Signal parent that we are in the correct namespaces.
        Zf(write(sync_pipe[1], "S", 1) != 1, "child failed to send sync signal");

        // Wait for parent to finish moving veth
        char ack;
        Zf(read(sync_pipe[1], &ack, 1) != 1 || ack != 'R', "child failed to receive ready signal");
        close(sync_pipe[1]);

        // Configure networking inside the new namespace.
        struct nl_sock *sock = nl_socket_alloc();
        Tf(sock != NULL, "failed to allocate netlink socket");
        Zf(nl_connect(sock, NETLINK_ROUTE) < 0, "failed to connect to netlink route socket");

        // Link names are based on the parent's PID (our PPID now).
        char veth_peer_name[IFNAMSIZ];
        snprintf(veth_peer_name, IFNAMSIZ, "veth-peer%05d", getpid() % 100000);
        
        // Get the link that was moved into our namespace.
        struct rtnl_link *link;
        Zf(rtnl_link_get_kernel(sock, 0, veth_peer_name, &link) < 0,
           "child failed to get link '%s'", veth_peer_name);
        
        // To modify the link, we create a new change object.
        errno = 0; // Clear errno before allocation
        struct rtnl_link *change = rtnl_link_alloc();
        if (change == NULL) {
           errno = ENOMEM; // Set errno to a more appropriate value
           Tf(change == NULL, "failed to allocate link for changes");
        }

        int if_index = rtnl_link_get_ifindex(link);
        rtnl_link_set_ifindex(change, if_index);

        // Set the new name to 'eth0' and bring the interface up in one operation.
        rtnl_link_set_name(change, veth_guest_name);
        rtnl_link_set_flags(change, IFF_UP);
        Zf(rtnl_link_change(sock, link, change, NLM_F_ACK) < 0,
           "failed to rename and bring up guest interface");
        
        rtnl_link_put(change);
        rtnl_link_put(link);

        // Set its IP address.
        struct rtnl_addr *addr = rtnl_addr_alloc();
        struct nl_addr *local_ip;
        char ip_str[INET_ADDRSTRLEN + 4];
        snprintf(ip_str, sizeof(ip_str), "%s/%d", inet_ntoa(guest_ip), cidr);
        Zf(nl_addr_parse(ip_str, AF_INET, &local_ip) < 0, "failed to parse guest address");
        rtnl_addr_set_local(addr, local_ip);
        nl_addr_put(local_ip);
        rtnl_addr_set_ifindex(addr, if_index);
        Zf(rtnl_addr_add(sock, addr, 0) < 0, "failed to add address to guest interface");
        rtnl_addr_put(addr);

        // Configure lo interface.
        struct rtnl_link *lo_link;
        Zf(rtnl_link_get_kernel(sock, 0, "lo", &lo_link) < 0, "failed to get loopback link");
        
        // To modify the link, we create a new change object.
        errno = 0; // Clear errno before allocation
        struct rtnl_link *lo_change = rtnl_link_alloc();
        if (lo_change == NULL) {
           errno = ENOMEM; // Set errno to a more appropriate value
           Tf(lo_change == NULL, "failed to allocate link for lo change");
        }

        rtnl_link_set_ifindex(lo_change, rtnl_link_get_ifindex(lo_link));
        rtnl_link_set_flags(lo_change, IFF_UP);

        Zf(rtnl_link_change(sock, lo_link, lo_change, NLM_F_ACK) < 0, "failed to bring up lo interface");

        rtnl_link_put(lo_change);
        rtnl_link_put(lo_link);
        
        // Set default route.
        struct rtnl_route *route = rtnl_route_alloc();
        
        struct nl_addr *dst;
        Zf(nl_addr_parse("0.0.0.0/0", AF_INET, &dst) < 0, "failed to parse route destination");
        Zf(rtnl_route_set_dst(route, dst) < 0, "failed to set route destination");
        nl_addr_put(dst);

        struct nl_addr *gw_addr;
        Zf(nl_addr_parse(inet_ntoa(bridge_ip), AF_INET, &gw_addr) < 0, "failed to parse gateway address");
        struct rtnl_nexthop *nh = rtnl_route_nh_alloc();
        rtnl_route_nh_set_ifindex(nh, if_index);
        rtnl_route_nh_set_gateway(nh, gw_addr);
        rtnl_route_add_nexthop(route, nh);
        nl_addr_put(gw_addr);
        Zf(rtnl_route_add(sock, route, 0) < 0, "failed to add default route");
        rtnl_route_put(route);
        
        nl_socket_free(sock);
        VERBOSE("child network configuration complete");

        // Add nameserver entries to /etc/resolv.conf
        FILE *resolv_conf = fopen("/etc/resolv.conf", "w");
        if (resolv_conf != NULL) {
            fprintf(resolv_conf, "nameserver 8.8.8.8\n"); // Google DNS
            fprintf(resolv_conf, "nameserver 1.1.1.1\n"); // Cloudflare DNS
            fclose(resolv_conf);
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