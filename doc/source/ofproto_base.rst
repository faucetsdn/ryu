**************************************************
OpenFlow version independent classes and functions
**************************************************

.. py:currentmodule:: ryu.ofproto.ofproto_parser

Base class for OpenFlow messages
--------------------------------

..    XXX
..    the descrption of _TYPE is inlined from ryu/lib/stringify.py.
..    this is a work around for a sphinx bug.
..    https://bitbucket.org/birkenfeld/sphinx/issue/741/autodoc-inherited-members-wont-work-for

.. autoclass:: MsgBase
   :members: to_jsondict, from_jsondict

   .. attribute::
    _TYPE

    _TYPE class attribute is used to annotate types of attributes.

    This type information is used to find an appropriate conversion for
    a JSON style dictionary.

    Currently the following types are implemented.

    ===== ==========
    Type  Descrption
    ===== ==========
    ascii US-ASCII
    utf-8 UTF-8
    ===== ==========

    Example::

        _TYPE = {
            'ascii': [
                'hw_addr',
            ],
            'utf-8': [
                'name',
            ]
        }

Functions
---------

.. autofunction:: ofp_msg_from_jsondict
