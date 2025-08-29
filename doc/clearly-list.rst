:code:`clearly list`
+++++++++++++++++++

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
  CONTAINER ID          IMAGE                 IP ADDRESS          STATUS     PORTS
  myapp                 example.com:5050/foo  10.0.0.1           Running    80/tcp, 443/tcp
  test-container        localhost:5000/test   10.0.0.2           Stopped    -

List all containers in JSON format:

::

  $ clearly list --json
  [
    {"id": "myapp", "image": "example.com:5050/foo", "ip_address": "10.0.0.1", "status": "Running", "ports": "80/tcp, 443/tcp"},
    {"id": "test-container", "image": "localhost:5000/test", "ip_address": "10.0.0.2", "status": "Stopped", "ports": ""}
  ]


.. include:: ./bugs.rst
.. include:: ./see_also.rst
