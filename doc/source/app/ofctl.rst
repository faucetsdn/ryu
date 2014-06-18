*************
ryu.app.ofctl
*************

ryu.app.ofctl provides a convenient way to use OpenFlow messages
synchronously.

OfctlService ryu application is automatically loaded if your
Ryu application imports ofctl.api module.

Example::

    import ryu.app.ofctl.api

OfctlService application internally uses OpenFlow barrier messages
to ensure message boundaries.  As OpenFlow messages are asynchronous
and some of messages does not have any replies on success, barriers
are necessary for correct error handling.

api module
==========

.. automodule:: ryu.app.ofctl.api
   :members:

exceptions
==========

.. automodule:: ryu.app.ofctl.exception
   :members:
