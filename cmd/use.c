/* This program sets the network interface for private traffic between machines.
   It takes a network interface name as an argument and attaches it to the "clearly0"
   bridge interface to enable private network communication.
   
   The program performs the following steps:
   1. Parses the network interface name from command line arguments
   2. Ensures the "clearly0" bridge interface exists (creates it if needed)
   3. Attaches the specified network interface to the bridge
   4. Reports success with "ok" message
   
   This is part of the Clearly container networking system, allowing nodes
   to configure network interfaces for container communication. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "misc.h"
#include "net.h"


const char usage[] = "\
Usage: use INTERFACE\n\
\n\
Set the network interface for private traffic between machines.\n\
\n\
Example:\n\
  $ clearly use eth1\n\
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

   /* Parse interface name. */
   const char *interface_name = argv[1];

   /* Ensure the network bridge exists. */
   if (!is_bridge_exists("clearly0")) {
      struct in_addr bridge_ip = { .s_addr = inet_addr("10.0.0.1") };
      create_bridge("clearly0", &bridge_ip, 8);
   }

   /* Attach physical interface to bridge.
   
      This section handles the enrolment of the physical interface to the bridge.
      
      1. Checking if the bridge already has a interface attached.
      2. If so, release the existing interface attachment.
      3. Attach the physical interface to the bridge.
      
      The physical interface will loose all its configuration and will cease
      to exist as a standalone interface and become a member of the bridge.
      At this point the bridge will be the 'master' of the interface. */
   set_bridge_attach("clearly0", interface_name); // TODO: Check if the interface is already attached.

   /* Report success. */
   printf("ok\n");
}
