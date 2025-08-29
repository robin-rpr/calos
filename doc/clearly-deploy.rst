:code:`clearly deploy`
+++++++++++++++++++++

.. only:: not man

   Deploy an application to the Clearly cluster using Docker Compose.


Synopsis
========

::

  $ clearly deploy [OPTION...] NAME
  $ clearly deploy [OPTION...] -f COMPOSE_FILE NAME


Description
===========

Deploy an application to the Clearly cluster by reading a Docker Compose file
and sending the services configuration to the Clearly daemon. The daemon will
handle the deployment across the cluster nodes.

The deploy command requires the Clearly daemon to be running and accessible
on the default API endpoint (http://127.0.0.1:8080).

  :code:`NAME`
    The name of the deployment. This identifier is used by the daemon to
    manage the deployed application.

  :code:`-f`, :code:`--file FILE`
    Specify an alternate compose file. If not specified, defaults to
    :code:`docker-compose.yml` in the current directory.

  :code:`-h`, :code:`--help`
    Print help and exit.

Examples
========

Deploy an application using the default compose file:

::

  $ clearly deploy myapp
  done

Deploy an application using a custom compose file:

::

  $ clearly deploy -f production.yml myapp
  done

Deploy using the long form of the file option:

::

  $ clearly deploy --file docker-compose.prod.yml myapp
  done

Deploy with a different application name:

::

  $ clearly deploy web-service
  done


.. include:: ./bugs.rst
.. include:: ./see_also.rst
