:code:`clearly list`
++++++++++++++++++++

.. only:: not man

   List all containers managed by the runtime.


Synopsis
========

::

  $ clearly list [OPTION...]


Description
===========

List all containers currently managed by the Clearly runtime, including their
container ID, image name, IP address, status, exposed ports, labels, and node
information. The command displays information about both running and stopped
containers across the entire cluster.

  :code:`--format FORMAT`
    Format output using a Go template. The default format is a table showing
    container ID, image, IP address, status, and ports. Available placeholders:
    :code:`{{.ID}}`, :code:`{{.Image}}`, :code:`{{.IP}}`, :code:`{{.Status}}`,
    :code:`{{.Ports}}`, :code:`{{.Labels}}`, :code:`{{.Node}}`.

  :code:`--no-trunc`
    Don't truncate output. By default, container IDs are truncated to 12
    characters and image names to 20 characters.

  :code:`-h`, :code:`--help`
    Print help and exit.

Examples
========

List all containers in default tabular format:

::

  $ clearly list
  CONTAINER ID          IMAGE                 IP ADDRESS          STATUS     PORTS
  myapp                 ubuntu:latest         10.0.0.1            Running    80->8080/tcp
  test-container        busybox:latest        -                   Stopped    -

List all containers with custom format including labels and node information:

::

  $ clearly list --format "table {{.ID}}\t{{.Image}}\t{{.Labels}}\t{{.Node}}"
  CONTAINER ID          IMAGE                 LABELS              NODE
  myapp                 ubuntu:latest         app=web,env=prod    4f8e9b7d3a214c54b76a9f4d2c0a1e3b
  test-container        busybox:latest        -                   c9d2f87b61f445b1992e5a37a4d83f0e


.. include:: ./bugs.rst
.. include:: ./see_also.rst
