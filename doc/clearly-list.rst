:code:`clearly list`
++++++++++++++++++++

.. only:: not man

   List all containers managed by the Clearly runtime.


Synopsis
========

::

  $ clearly list [OPTION...]


Description
===========

List all containers currently managed by the Clearly runtime, including their
container ID, image name, IP address, status, and exposed ports. The command
displays information about both running and stopped containers.

  :code:`--json`
    Output the container list in JSON format instead of the default tabular
    format. This is useful for programmatic processing of the output.

  :code:`-h`, :code:`--help`
    Print help and exit.

Examples
========

List all containers in tabular format:

::

  $ clearly list
  CONTAINER ID          IMAGE                 IP ADDRESS          STATUS     PORTS              LABELS
  myapp                 ubuntu:latest         10.0.0.1            Running    80->8080/tcp       -
  test-container        busybox:latest        -                   Stopped    -                  -

List all containers in JSON format:

::

  $ clearly list --json
  [
    {"id": "myapp", "image": "ubuntu:latest", "ip": "10.0.0.1", "status": "Running", "ports": {"80":"8080/tcp"}, "labels": {}},
    {"id": "test-container", "image": "busybox:latest", "ip": "", "status": "Stopped", "ports": {}, "labels": {}}
  ]


.. include:: ./bugs.rst
.. include:: ./see_also.rst
