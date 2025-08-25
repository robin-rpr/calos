What is Clearly?
---------------------

Clearly provides user-defined software stacks (UDSS) for high-performance
computing (HPC) centers. This "bring your own software stack" functionality
addresses needs such as:

* software dependencies that are numerous, complex, unusual, differently
  configured, or simply newer/older than what the center provides;

* build-time requirements unavailable within the center, such as relatively
  unfettered internet access;

* validated software stacks and configuration to meet the standards of a
  particular field of inquiry;

* portability of environments between resources, including workstations and
  other test and development system not managed by the center;

* consistent environments, even archivally so, that can be easily, reliably,
  and verifiably reproduced in the future; and/or

* usability and comprehensibility.

How does it work?
-----------------

Clearly uses Linux user namespaces to run containers with no privileged
operations or daemons and minimal configuration changes on center resources.
This simple approach avoids most security risks while maintaining access to
the performance and functionality already on offer.

Container images can be built using Docker or anything else that can generate
a standard Linux filesystem tree.

Quick Installation
------------------

To build from source:

1. Generate build system: ``./autogen.sh``
2. Configure: ``./configure``
3. Build and install: ``make && sudo make install``

For more, see the `INSTALL.rst` file.

How do I learn more?
--------------------

* Documentation: https://hpc.github.io/charliecloud

* GitLab repository: https://gitlab.com/charliecloud/main

* Mailing lists: https://lists.charliecloud.io

* We wrote an article for USENIX's magazine *;login:* that explains in more
  detail the motivation for Clearly and the technology upon which it is
  based: https://www.usenix.org/publications/login/fall2017/priedhorsky

* For technical papers about Clearly, refer to the *Technical
  publications* section below.

License and intellectual property
---------------------------------

Clearly is open source software; you can redistribute it and/or modify it
under the terms of the Apache License, Version 2.0. A copy is included in file
LICENSE. You may not use this software except in compliance with the license.

Copyrights and patents are retained by contributors. No copyright assignment
is required to contribute to Clearly.


..  LocalWords:  USENIX's CNA Meisam figshare
