*****************
OF-Config support
*****************

Ryu has a library for OF-Config support.

XML schema files for NETCONFIG and OFConfig
===========================================
XML schema files for NETCONF and OFConfig are stolen from LINC whose licence
is Apache 2.0.
It supports only part of OFConfig so that its schema files are (intentionally)
limited such that operation attributes are allowed only in several limited
places.
Once our library is tested with other OFConfig switches, the schema files
should be updated to allow operation attribute in more places.

References
==========
* `NETCONF ietf <http://datatracker.ietf.org/wg/netconf/>`_,
* `NETCONF ietf wiki <http://tools.ietf.org/wg/netconf/trac/wiki>`_,
* `OF-Config spec <https://www.opennetworking.org/standards/of-config>`_,
* `ncclient <http://ncclient.grnet.gr/>`_,
* `ncclient repo <https://github.com/leopoul/ncclient/>`_,
* `LINC git repo <https://github.com/FlowForwarding>`_
