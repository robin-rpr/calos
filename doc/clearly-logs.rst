:code:`clearly logs`
++++++++++++++++++++

.. only:: not man

   Show logs from a running container.


Synopsis
========

::

  $ clearly logs [OPTION...] CONTAINER_ID


Description
===========

Display the stdout and stderr output from a running container. The logs command
reads from the container's log file and displays the output to the terminal.
This is useful for debugging and monitoring container applications.

  :code:`CONTAINER_ID`
    The identifier of the container whose logs should be displayed. This can be
    the container name or the full container ID.

  :code:`-f`, :code:`--follow`
    Follow the log output in real-time, similar to :code:`tail -f`. The command
    will continue running and display new log entries as they are written.

  :code:`-h`, :code:`--help`
    Print help and exit.

Examples
========

Show all logs from a container:

::

  $ clearly logs myapp
  2024-01-15 10:30:15 INFO Starting application...
  2024-01-15 10:30:16 INFO Server listening on port 8080
  2024-01-15 10:30:17 INFO Database connection established

Follow logs in real-time:

::

  $ clearly logs -f myapp
  2024-01-15 10:30:15 INFO Starting application...
  2024-01-15 10:30:16 INFO Server listening on port 8080
  2024-01-15 10:30:17 INFO Database connection established
  2024-01-15 10:31:23 INFO New request received from 192.168.1.100
  2024-01-15 10:31:24 INFO Request processed successfully

Show logs using container ID:

::

  $ clearly logs abc123def456
  2024-01-15 10:30:15 INFO Starting application...


.. include:: ./bugs.rst
.. include:: ./see_also.rst
