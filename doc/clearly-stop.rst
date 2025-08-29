:code:`clearly stop`
++++++++++++++++++++

.. only:: not man

   Stop a running container gracefully.


Synopsis
========

::

  $ clearly stop CONTAINER_ID


Description
===========

Stop a running container by sending a SIGTERM signal to the container process.
The command waits for the container to stop gracefully within 3 seconds. If the
container does not stop within this time, a SIGKILL signal is sent to force
termination.

The stop command is the recommended way to terminate containers as it allows
the application inside the container to perform cleanup operations before
shutting down.

  :code:`CONTAINER_ID`
    The identifier of the container to stop. This can be the container name or
    the full container ID.

  :code:`-h`, :code:`--help`
    Print help and exit.

Examples
========

Stop a container by name:

::

  $ clearly stop myapp
  done

Stop a container by ID:

::

  $ clearly stop abc123def456
  done

Stop a container that doesn't respond to SIGTERM:

::

  $ clearly stop stubborn-app
  container did not stop gracefully. sending SIGKILL...
  done


.. include:: ./bugs.rst
.. include:: ./see_also.rst
