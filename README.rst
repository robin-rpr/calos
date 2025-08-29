What is Clearly?
================

Clearly is a containerization and orchestration platform that provides
comprehensive tools for building, running, and deploying applications in
isolated environments. The platform operates entirely in user space without
requiring privileged operations, making it suitable for deployment in various
environments from development workstations to production clusters.

Clearly addresses application deployment needs such as:

* **Application Isolation**: Run applications in isolated containers with
  controlled access to system resources and filesystems.

* **Resource Management**: Fine-grained control over CPU, memory, network
  resources, and process limits for containerized applications.

* **Multi-Service Deployment**: Orchestrate complex applications consisting
  of multiple services using Docker Compose syntax and cluster deployment.

* **Development Consistency**: Create reproducible development environments
  that can be easily shared and deployed across different systems.

* **Network Configuration**: Configure container networking with static IP
  addresses, port forwarding, and inter-container communication.

* **Image Management**: Build, convert, and manage container images in
  multiple formats including directories, SquashFS archives, and
  Docker-compatible images.

Core Components
===============

The Clearly platform consists of several command-line tools that provide
different aspects of container management:

* **:code:`clearly run`**: Execute commands in isolated containers with
  comprehensive resource and network control.

* **:code:`clearly image`**: Build and manage container images from
  Dockerfiles or existing images, with support for multiple output formats.

* **:code:`clearly deploy`**: Deploy multi-service applications to clusters
  using Docker Compose configuration files.

* **:code:`clearly list`**: Display information about running containers
  including their status, IP addresses, and resource usage.

* **:code:`clearly logs`**: Access and monitor application output from
  running containers in real-time.

* **:code:`clearly stop`**: Gracefully terminate running containers with
  proper signal handling and cleanup.

* **:code:`clearly daemon`**: Cluster orchestration service that manages
  container deployment and lifecycle across multiple nodes.

* **:code:`clearly convert`**: Convert container images between different
  formats for deployment in various environments.

* **:code:`clearly check`**: Verify system prerequisites and configuration
  for running Clearly containers.

Technical Approach
==================

Clearly uses Linux user namespaces to provide container isolation without
requiring privileged operations or system daemons. This approach ensures:

* **Security**: No privileged operations, setuid binaries, or root access
  required for container execution.

* **Portability**: Works on any Linux system with user namespace support,
  including development workstations and production servers.

* **Performance**: Minimal overhead with direct access to host resources
  while maintaining proper isolation boundaries.

* **Simplicity**: Straightforward deployment and management without complex
  infrastructure requirements or configuration changes.

The platform includes a daemon service that provides cluster orchestration
capabilities, allowing deployment of applications across multiple nodes
using familiar Docker Compose syntax. The daemon manages container lifecycle,
resource allocation, and inter-container communication within the cluster.

Installation
============

To install Clearly from source:

1. Generate build system: :code:`./autogen.sh`
2. Configure: :code:`./configure`
3. Build and install: :code:`make && sudo make install`

For binary installation, use the provided installation script:

::

  $ curl -fsSL https://clearly.run/install.sh | sh

Quick Start
===========

Build and run a simple application:

::

  $ clearly image build .
  inferred image name: myapp
  grown in 3 instructions: myapp
  $ clearly run myapp -- python app.py
  Hello from Clearly container

Deploy a multi-service application:

::

  $ clearly deploy myapp
  done

For detailed usage instructions and examples, see the `INSTALL.rst` file
and the full documentation at https://clearly.run.

..  LocalWords:  USENIX's CNA Meisam figshare
