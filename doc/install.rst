Installing
**********

Note that installing and using Clearly can be done as a normal user with no elevated privileges, provided that user namespaces have been enabled.
Out of the box, Clearly is a high-performance rootless container engine.

.. code-block:: bash

   $ curl -fsSL https://clearly.run/install.sh | sh

Start the Service
=================

After installing, you can unlock Clearly's full distributed clustering power via:

.. code-block:: bash

   $ service clearly start

This launches Clearly’s distributed clustering engine. It will automatically discover and join other Clearly nodes, and bring up the dashboard at http://localhost:8080
From there, you can create Studios, orchestrate containers, manage deployments, and steer your Clearly cluster with ease.

..  LocalWords:  Werror Flameeyes plougher deps libc’s ericonr
