/* This program creates a VXLAN (Virtual Extensible LAN) connection to a remote node.
   It takes a remote IP address as an argument and establishes a virtual network link
   between the local system and the specified remote node.
   
   The program performs the following steps:
   1. Parses the remote IP address from command line arguments
   2. Finds an unused VXLAN interface name, to avoid link name collisions
   3. Checks if a VXLAN interface already exists for the given remote IP
   4. If no VXLAN exists, creates a new VXLAN interface
   5. Bridges the VXLAN to the "clearly0" bridge interface
   6. Reports success with "ok" message
   
   This is part of the Clearly container networking system, allowing nodes
   to establish virtual network connections for container communication. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "config.h"
#include "misc.h"
#include "net.h"


const char usage[] = "\
Usage: link REMOTE VNI\n\
\n\
Link with VXLAN using VNI (Virtual Network Identifier) to remote node.\n\
\n\
Example:\n\
\n\
  $ clearly link 172.20.0.10 1234\n\
  ok\n";

#define TRY(x) if (x) fatal_(__FILE__, __LINE__, errno, #x)


void fatal_(const char *file, int line, int errno_, const char *str)
{
   printf("error: %s: %d: %s\n", file, line, str);
   printf("errno: %d\n", errno_);
   exit(EXIT_MISC_ERR);
}

int main(int argc, char *argv[])
{
   if ((argc >= 2 && strcmp(argv[1], "--help") == 0)) {
      fprintf(stderr, usage);
      return 0;
   }
   if (argc < 2) {
      fprintf(stderr, usage);
      return 1;
   }

   /* Parse remote IP. */
   struct in_addr remote_ip;
   if (argc >= 2) {
      remote_ip.s_addr = inet_addr(argv[1]);
   } else {
      fprintf(stderr, usage);
      fprintf(stderr, "link: error: the following arguments are required: REMOTE");
      return 1;
   }

   /* Parse VNI. */
   uint32_t vni;
   if (argc >= 3) {
      vni = strtoul(argv[2], NULL, 10);
   } else {
      fprintf(stderr, usage);
      fprintf(stderr, "link: error: the following arguments are required: VNI");
      return 1;
   }

   /* Find an unused VXLAN interface name.
   
      We need to create a unique VXLAN interface name since multiple VXLAN
      connections may exist simultaneously. We iterate through names like
      "vxlan1", "vxlan2", etc. until we find one that doesn't already exist.
      
      This prevents conflicts when establishing multiple network links to
      different remote nodes, as each VXLAN interface must have a unique
      identifier in the system. */
   char vxlan_name[IFNAMSIZ];
   int vxlan_index = 1;
   for (;;) {
      TRY(snprintf(vxlan_name, sizeof(vxlan_name), "vxlan%d", vxlan_index) < 0);
      if (!is_link_exists(vxlan_name))
         break;
      if (vxlan_index >= INT_MAX) {
         Zf(1, "VXLAN name index overflow");
      }
      vxlan_index++;
   }

   /* Provision VXLAN interface and attach to bridge.
   
      This section handles the creation and configuration of a VXLAN (Virtual
      Extensible LAN) interface with VNI 4242 to establish a network tunnel to
      the remote node. The process involves:
      
      1. Checking if a VXLAN interface already exists for the target remote IP
      2. If not, creating a new VXLAN interface with the generated unique name
      3. Attaching the VXLAN interface to the "clearly0" bridge to enable
         Layer 2 connectivity between the local and remote networks
      
      The VXLAN interface acts as a virtual network link that encapsulates
      Ethernet frames in UDP packets, allowing transparent communication
      across the underlying network infrastructure. */
   if (!is_vxlan_exists(vni, "*", &remote_ip)) {
      create_vxlan(vxlan_name, vni, &remote_ip);
      INFO("Created VXLAN interface %s", vxlan_name);
      set_vxlan_bridge(vxlan_name, "clearly0");
      INFO("Attached VXLAN interface %s to bridge clearly0", vxlan_name);
   }   

   /* Report success. */
   printf("ok\n");
}
