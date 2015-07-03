# Copyright (C) 2014 Xinguard, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
BFD Control packet parser/serializer

RFC 5880
BFD Control packet format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       My Discriminator                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Your Discriminator                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Desired Min TX Interval                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Required Min RX Interval                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Required Min Echo RX Interval                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   An optional Authentication Section MAY be present in the following
   format of types:

   1. Format of Simple Password Authentication Section

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Auth Type   |   Auth Len    |  Auth Key ID  |  Password...  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              ...                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   2. Format of Keyed MD5 and Meticulous Keyed MD5 Authentication Section

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Auth Key/Digest...                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              ...                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   3. Format of Keyed SHA1 and Meticulous Keyed SHA1 Authentication Section

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Auth Key/Hash...                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              ...                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
import binascii
import hashlib
import random
import six
import struct

from . import packet_base
from ryu.lib import addrconv
from ryu.lib import stringify

BFD_STATE_ADMIN_DOWN = 0
BFD_STATE_DOWN = 1
BFD_STATE_INIT = 2
BFD_STATE_UP = 3

BFD_STATE_NAME = {0: "AdminDown",
                  1: "Down",
                  2: "Init",
                  3: "Up"}

BFD_FLAG_POLL = 1 << 5
BFD_FLAG_FINAL = 1 << 4
BFD_FLAG_CTRL_PLANE_INDEP = 1 << 3
BFD_FLAG_AUTH_PRESENT = 1 << 2
BFD_FLAG_DEMAND = 1 << 1
BFD_FLAG_MULTIPOINT = 1

BFD_DIAG_NO_DIAG = 0
BFD_DIAG_CTRL_DETECT_TIME_EXPIRED = 1
BFD_DIAG_ECHO_FUNC_FAILED = 2
BFD_DIAG_NEIG_SIG_SESS_DOWN = 3
BFD_DIAG_FWD_PLANE_RESET = 4
BFD_DIAG_PATH_DOWN = 5
BFD_DIAG_CONCAT_PATH_DOWN = 6
BFD_DIAG_ADMIN_DOWN = 7
BFD_DIAG_REV_CONCAT_PATH_DOWN = 8

BFD_DIAG_CODE_NAME = {0: "No Diagnostic",
                      1: "Control Detection Time Expired",
                      2: "Echo Function Failed",
                      3: "Neighbor Signaled Session Down",
                      4: "Forwarding Plane Reset",
                      5: "Path Down",
                      6: "Concatenated Path Down",
                      7: "Administratively Down",
                      8: "Reverse Concatenated Path Down"}

BFD_AUTH_RESERVED = 0
BFD_AUTH_SIMPLE_PASS = 1
BFD_AUTH_KEYED_MD5 = 2
BFD_AUTH_METICULOUS_KEYED_MD5 = 3
BFD_AUTH_KEYED_SHA1 = 4
BFD_AUTH_METICULOUS_KEYED_SHA1 = 5

BFD_AUTH_TYPE_NAME = {0: "Reserved",
                      1: "Simple Password",
                      2: "Keyed MD5",
                      3: "Meticulous Keyed MD5",
                      4: "Keyed SHA1",
                      5: "Meticulous Keyed SHA1"}


class bfd(packet_base.PacketBase):
    """BFD (RFC 5880) Control packet encoder/decoder class.

    The serialized packet would looks like the ones described
    in the following sections.

    * RFC 5880 Generic BFD Control Packet Format

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.

    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    ============================== ============================================
    Attribute                      Description
    ============================== ============================================
    ver                            The version number of the protocol.
                                   This class implements protocol version 1.
    diag                           A diagnostic code specifying the local
                                   system's reason for the last change in
                                   session state.
    state                          The current BFD session state as seen by
                                   the transmitting system.
    flags                          Bitmap of the following flags.

                                   | BFD_FLAG_POLL
                                   | BFD_FLAG_FINAL
                                   | BFD_FLAG_CTRL_PLANE_INDEP
                                   | BFD_FLAG_AUTH_PRESENT
                                   | BFD_FLAG_DEMAND
                                   | BFD_FLAG_MULTIPOINT
    detect_mult                    Detection time multiplier.
    my_discr                       My Discriminator.
    your_discr                     Your Discriminator.
    desired_min_tx_interval        Desired Min TX Interval. (in microseconds)
    required_min_rx_interval       Required Min RX Interval. (in microseconds)
    required_min_echo_rx_interval  Required Min Echo RX Interval.
                                   (in microseconds)
    auth_cls                       (Optional) Authentication Section instance.
                                   It's defined only when the Authentication
                                   Present (A) bit is set in flags.
                                   Assign an instance of the following classes:
                                   ``SimplePassword``, ``KeyedMD5``,
                                   ``MeticulousKeyedMD5``, ``KeyedSHA1``, and
                                   ``MeticulousKeyedSHA1``.
    length                         (Optional) Length of the BFD Control packet,
                                   in bytes.
    ============================== ============================================
    """

    _PACK_STR = '!BBBBIIIII'
    _PACK_STR_LEN = struct.calcsize(_PACK_STR)

    _TYPE = {
        'ascii': []
    }

    _auth_parsers = {}

    def __init__(self, ver=1, diag=0, state=0, flags=0, detect_mult=0,
                 my_discr=0, your_discr=0, desired_min_tx_interval=0,
                 required_min_rx_interval=0, required_min_echo_rx_interval=0,
                 auth_cls=None, length=None):
        super(bfd, self).__init__()

        self.ver = ver
        self.diag = diag
        self.state = state
        self.flags = flags
        self.detect_mult = detect_mult
        self.my_discr = my_discr
        self.your_discr = your_discr
        self.desired_min_tx_interval = desired_min_tx_interval
        self.required_min_rx_interval = required_min_rx_interval
        self.required_min_echo_rx_interval = required_min_echo_rx_interval
        self.auth_cls = auth_cls
        if isinstance(length, int):
            self.length = length
        else:
            self.length = len(self)

    def __len__(self):
        if self.flags & BFD_FLAG_AUTH_PRESENT and self.auth_cls is not None:
            return self._PACK_STR_LEN + len(self.auth_cls)
        else:
            return self._PACK_STR_LEN

    @classmethod
    def parser(cls, buf):
        (diag, flags, detect_mult, length, my_discr, your_discr,
         desired_min_tx_interval, required_min_rx_interval,
         required_min_echo_rx_interval) = \
            struct.unpack_from(cls._PACK_STR, buf[:cls._PACK_STR_LEN])

        ver = diag >> 5
        diag = diag & 0x1f
        state = flags >> 6
        flags = flags & 0x3f

        if flags & BFD_FLAG_AUTH_PRESENT:
            auth_type = six.indexbytes(buf, cls._PACK_STR_LEN)
            auth_cls = cls._auth_parsers[auth_type].\
                parser(buf[cls._PACK_STR_LEN:])[0]
        else:
            auth_cls = None

        msg = cls(ver, diag, state, flags, detect_mult,
                  my_discr, your_discr, desired_min_tx_interval,
                  required_min_rx_interval, required_min_echo_rx_interval,
                  auth_cls)

        return msg, None, None

    def serialize(self, payload, prev):
        if self.flags & BFD_FLAG_AUTH_PRESENT and self.auth_cls is not None:
            return self.pack() + \
                self.auth_cls.serialize(payload=None, prev=self)
        else:
            return self.pack()

    def pack(self):
        """
        Encode a BFD Control packet without authentication section.
        """
        diag = (self.ver << 5) + self.diag
        flags = (self.state << 6) + self.flags
        length = len(self)

        return struct.pack(self._PACK_STR, diag, flags, self.detect_mult,
                           length, self.my_discr, self.your_discr,
                           self.desired_min_tx_interval,
                           self.required_min_rx_interval,
                           self.required_min_echo_rx_interval)

    def authenticate(self, *args, **kwargs):
        """Authenticate this packet.

        Returns a boolean indicates whether the packet can be authenticated
        or not.

        Returns ``False`` if the Authentication Present (A) is not set in the
        flag of this packet.

        Returns ``False`` if the Authentication Section for this packet is not
        present.

        For the description of the arguemnts of this method, refer to the
        authentication method of the Authentication Section classes.
        """
        if not self.flags & BFD_FLAG_AUTH_PRESENT or \
                not issubclass(self.auth_cls.__class__, BFDAuth):
            return False

        return self.auth_cls.authenticate(self, *args, **kwargs)

    @classmethod
    def set_auth_parser(cls, auth_cls):
        cls._auth_parsers[auth_cls.auth_type] = auth_cls

    @classmethod
    def register_auth_type(cls, auth_type):
        def _set_type(auth_cls):
            auth_cls.set_type(auth_cls, auth_type)
            cls.set_auth_parser(auth_cls)
            return auth_cls
        return _set_type


class BFDAuth(stringify.StringifyMixin):
    """Base class of BFD (RFC 5880) Authentication Section

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.

    .. tabularcolumns:: |l|L|

    =========== ============================================
    Attribute   Description
    =========== ============================================
    auth_type   The authentication type in use.
    auth_len    The length, in bytes, of the authentication
                section, including the ``auth_type`` and
                ``auth_len`` fields.
    =========== ============================================
    """
    _PACK_HDR_STR = '!BB'
    _PACK_HDR_STR_LEN = struct.calcsize(_PACK_HDR_STR)

    auth_type = None

    def __init__(self, auth_len=None):
        super(BFDAuth, self).__init__()
        if isinstance(auth_len, int):
            self.auth_len = auth_len
        else:
            self.auth_len = len(self)

    @staticmethod
    def set_type(subcls, auth_type):
        assert issubclass(subcls, BFDAuth)
        subcls.auth_type = auth_type

    @classmethod
    def parser_hdr(cls, buf):
        """
        Parser for common part of authentication section.
        """
        return struct.unpack_from(cls._PACK_HDR_STR,
                                  buf[:cls._PACK_HDR_STR_LEN])

    def serialize_hdr(self):
        """
        Serialization function for common part of authentication section.
        """
        return struct.pack(self._PACK_HDR_STR, self.auth_type, self.auth_len)


@bfd.register_auth_type(BFD_AUTH_SIMPLE_PASS)
class SimplePassword(BFDAuth):
    """ BFD (RFC 5880) Simple Password Authentication Section class

    An instance has the following attributes.
    Most of them are same to the on-wire counterparts but in host byte order.

    .. tabularcolumns:: |l|L|

    =========== ============================================
    Attribute   Description
    =========== ============================================
    auth_type   (Fixed) The authentication type in use.
    auth_key_id The authentication Key ID in use.
    password    The simple password in use on this session.
                The password is a binary string, and MUST be
                from 1 to 16 bytes in length.
    auth_len    The length, in bytes, of the authentication
                section, including the ``auth_type`` and
                ``auth_len`` fields.
    =========== ============================================
    """
    _PACK_STR = '!B'
    _PACK_STR_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, auth_key_id, password, auth_len=None):
        assert len(password) >= 1 and len(password) <= 16
        self.auth_key_id = auth_key_id
        self.password = password
        super(SimplePassword, self).__init__(auth_len)

    def __len__(self):
        return self._PACK_HDR_STR_LEN + self._PACK_STR_LEN + len(self.password)

    @classmethod
    def parser(cls, buf):
        (auth_type, auth_len) = cls.parser_hdr(buf)
        assert auth_type == cls.auth_type

        auth_key_id = six.indexbytes(buf, cls._PACK_HDR_STR_LEN)

        password = buf[cls._PACK_HDR_STR_LEN + cls._PACK_STR_LEN:auth_len]

        msg = cls(auth_key_id, password, auth_len)

        return msg, None, None

    def serialize(self, payload, prev):
        """Encode a Simple Password Authentication Section.

        ``payload`` is the rest of the packet which will immediately follow
        this section.

        ``prev`` is a ``bfd`` instance for the BFD Control header. It's not
        necessary for encoding only the Simple Password section.
        """
        return self.serialize_hdr() + \
            struct.pack(self._PACK_STR, self.auth_key_id) + self.password

    def authenticate(self, prev=None, auth_keys={}):
        """Authenticate the password for this packet.

        This method can be invoked only when ``self.password`` is defined.

        Returns a boolean indicates whether the password can be authenticated
        or not.

        ``prev`` is a ``bfd`` instance for the BFD Control header. It's not
        necessary for authenticating the Simple Password.

        ``auth_keys`` is a dictionary of authentication key chain which
        key is an integer of *Auth Key ID* and value is a string of *Password*.
        """
        assert isinstance(prev, bfd)
        if self.auth_key_id in auth_keys and \
                self.password == auth_keys[self.auth_key_id]:
            return True
        else:
            return False


@bfd.register_auth_type(BFD_AUTH_KEYED_MD5)
class KeyedMD5(BFDAuth):
    """ BFD (RFC 5880) Keyed MD5 Authentication Section class

    An instance has the following attributes.
    Most of them are same to the on-wire counterparts but in host byte order.

    .. tabularcolumns:: |l|L|

    =========== =================================================
    Attribute   Description
    =========== =================================================
    auth_type   (Fixed) The authentication type in use.
    auth_key_id The authentication Key ID in use.
    seq         The sequence number for this packet.
                This value is incremented occasionally.
    auth_key    The shared MD5 key for this packet.
    digest      (Optional) The 16-byte MD5 digest for the packet.
    auth_len    (Fixed) The length of the authentication section
                is 24 bytes.
    =========== =================================================
    """
    _PACK_STR = '!BBL16s'
    _PACK_STR_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, auth_key_id, seq, auth_key=None, digest=None,
                 auth_len=None):
        self.auth_key_id = auth_key_id
        self.seq = seq
        self.auth_key = auth_key
        self.digest = digest
        super(KeyedMD5, self).__init__(auth_len)

    def __len__(self):
        # Defined in RFC5880 Section 4.3.
        return 24

    @classmethod
    def parser(cls, buf):
        (auth_type, auth_len) = cls.parser_hdr(buf)
        assert auth_type == cls.auth_type
        assert auth_len == 24

        (auth_key_id, reserved, seq, digest) = \
            struct.unpack_from(cls._PACK_STR, buf[cls._PACK_HDR_STR_LEN:])
        assert reserved == 0

        msg = cls(auth_key_id=auth_key_id, seq=seq, auth_key=None,
                  digest=digest)

        return msg, None, None

    def serialize(self, payload, prev):
        """Encode a Keyed MD5 Authentication Section.

        This method is used only when encoding an BFD Control packet.

        ``payload`` is the rest of the packet which will immediately follow
        this section.

        ``prev`` is a ``bfd`` instance for the BFD Control header which this
        authentication section belongs to. It's necessary to be assigned
        because an MD5 digest must be calculated over the entire BFD Control
        packet.
        """
        assert self.auth_key is not None and len(self.auth_key) <= 16
        assert isinstance(prev, bfd)

        bfd_bin = prev.pack()
        auth_hdr_bin = self.serialize_hdr()
        auth_data_bin = struct.pack(self._PACK_STR, self.auth_key_id, 0,
                                    self.seq, self.auth_key +
                                    (b'\x00' * (len(self.auth_key) - 16)))

        h = hashlib.md5()
        h.update(bfd_bin + auth_hdr_bin + auth_data_bin)
        self.digest = h.digest()

        return auth_hdr_bin + struct.pack(self._PACK_STR, self.auth_key_id, 0,
                                          self.seq, self.digest)

    def authenticate(self, prev, auth_keys={}):
        """Authenticate the MD5 digest for this packet.

        This method can be invoked only when ``self.digest`` is defined.

        Returns a boolean indicates whether the digest can be authenticated
        by the correspondent Auth Key or not.

        ``prev`` is a ``bfd`` instance for the BFD Control header which this
        authentication section belongs to. It's necessary to be assigned
        because an MD5 digest must be calculated over the entire BFD Control
        packet.

        ``auth_keys`` is a dictionary of authentication key chain which
        key is an integer of *Auth Key ID* and value is a string of *Auth Key*.
        """
        assert isinstance(prev, bfd)

        if self.digest is None:
            return False

        if self.auth_key_id not in auth_keys:
            return False

        auth_key = auth_keys[self.auth_key_id]

        bfd_bin = prev.pack()
        auth_hdr_bin = self.serialize_hdr()
        auth_data_bin = struct.pack(self._PACK_STR, self.auth_key_id, 0,
                                    self.seq, auth_key +
                                    (b'\x00' * (len(auth_key) - 16)))

        h = hashlib.md5()
        h.update(bfd_bin + auth_hdr_bin + auth_data_bin)

        if self.digest == h.digest():
            return True
        else:
            return False


@bfd.register_auth_type(BFD_AUTH_METICULOUS_KEYED_MD5)
class MeticulousKeyedMD5(KeyedMD5):
    """ BFD (RFC 5880) Meticulous Keyed MD5 Authentication Section class

    All methods of this class are inherited from ``KeyedMD5``.

    An instance has the following attributes.
    Most of them are same to the on-wire counterparts but in host byte order.

    .. tabularcolumns:: |l|L|

    =========== =================================================
    Attribute   Description
    =========== =================================================
    auth_type   (Fixed) The authentication type in use.
    auth_key_id The authentication Key ID in use.
    seq         The sequence number for this packet.
                This value is incremented for each
                successive packet transmitted for a session.
    auth_key    The shared MD5 key for this packet.
    digest      (Optional) The 16-byte MD5 digest for the packet.
    auth_len    (Fixed) The length of the authentication section
                is 24 bytes.
    =========== =================================================
    """
    pass


@bfd.register_auth_type(BFD_AUTH_KEYED_SHA1)
class KeyedSHA1(BFDAuth):
    """ BFD (RFC 5880) Keyed SHA1 Authentication Section class

    An instance has the following attributes.
    Most of them are same to the on-wire counterparts but in host byte order.

    .. tabularcolumns:: |l|L|

    =========== ================================================
    Attribute   Description
    =========== ================================================
    auth_type   (Fixed) The authentication type in use.
    auth_key_id The authentication Key ID in use.
    seq         The sequence number for this packet.
                This value is incremented occasionally.
    auth_key    The shared SHA1 key for this packet.
    auth_hash   (Optional) The 20-byte SHA1 hash for the packet.
    auth_len    (Fixed) The length of the authentication section
                is 28 bytes.
    =========== ================================================
    """
    _PACK_STR = '!BBL20s'
    _PACK_STR_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, auth_key_id, seq, auth_key=None, auth_hash=None,
                 auth_len=None):
        self.auth_key_id = auth_key_id
        self.seq = seq
        self.auth_key = auth_key
        self.auth_hash = auth_hash
        super(KeyedSHA1, self).__init__(auth_len)

    def __len__(self):
        # Defined in RFC5880 Section 4.4.
        return 28

    @classmethod
    def parser(cls, buf):
        (auth_type, auth_len) = cls.parser_hdr(buf)
        assert auth_type == cls.auth_type
        assert auth_len == 28

        (auth_key_id, reserved, seq, auth_hash) = \
            struct.unpack_from(cls._PACK_STR, buf[cls._PACK_HDR_STR_LEN:])
        assert reserved == 0

        msg = cls(auth_key_id=auth_key_id, seq=seq, auth_key=None,
                  auth_hash=auth_hash)

        return msg, None, None

    def serialize(self, payload, prev):
        """Encode a Keyed SHA1 Authentication Section.

        This method is used only when encoding an BFD Control packet.

        ``payload`` is the rest of the packet which will immediately follow
        this section.

        ``prev`` is a ``bfd`` instance for the BFD Control header which this
        authentication section belongs to. It's necessary to be assigned
        because an SHA1 hash must be calculated over the entire BFD Control
        packet.
        """
        assert self.auth_key is not None and len(self.auth_key) <= 20
        assert isinstance(prev, bfd)

        bfd_bin = prev.pack()
        auth_hdr_bin = self.serialize_hdr()
        auth_data_bin = struct.pack(self._PACK_STR, self.auth_key_id, 0,
                                    self.seq, self.auth_key +
                                    (b'\x00' * (len(self.auth_key) - 20)))

        h = hashlib.sha1()
        h.update(bfd_bin + auth_hdr_bin + auth_data_bin)
        self.auth_hash = h.digest()

        return auth_hdr_bin + struct.pack(self._PACK_STR, self.auth_key_id, 0,
                                          self.seq, self.auth_hash)

    def authenticate(self, prev, auth_keys={}):
        """Authenticate the SHA1 hash for this packet.

        This method can be invoked only when ``self.auth_hash`` is defined.

        Returns a boolean indicates whether the hash can be authenticated
        by the correspondent Auth Key or not.

        ``prev`` is a ``bfd`` instance for the BFD Control header which this
        authentication section belongs to. It's necessary to be assigned
        because an SHA1 hash must be calculated over the entire BFD Control
        packet.

        ``auth_keys`` is a dictionary of authentication key chain which
        key is an integer of *Auth Key ID* and value is a string of *Auth Key*.
        """
        assert isinstance(prev, bfd)

        if self.auth_hash is None:
            return False

        if self.auth_key_id not in auth_keys:
            return False

        auth_key = auth_keys[self.auth_key_id]

        bfd_bin = prev.pack()
        auth_hdr_bin = self.serialize_hdr()
        auth_data_bin = struct.pack(self._PACK_STR, self.auth_key_id, 0,
                                    self.seq, auth_key +
                                    (b'\x00' * (len(auth_key) - 20)))

        h = hashlib.sha1()
        h.update(bfd_bin + auth_hdr_bin + auth_data_bin)

        if self.auth_hash == h.digest():
            return True
        else:
            return False


@bfd.register_auth_type(BFD_AUTH_METICULOUS_KEYED_SHA1)
class MeticulousKeyedSHA1(KeyedSHA1):
    """ BFD (RFC 5880) Meticulous Keyed SHA1 Authentication Section class

    All methods of this class are inherited from ``KeyedSHA1``.

    An instance has the following attributes.
    Most of them are same to the on-wire counterparts but in host byte order.

    .. tabularcolumns:: |l|L|

    =========== ================================================
    Attribute   Description
    =========== ================================================
    auth_type   (Fixed) The authentication type in use.
    auth_key_id The authentication Key ID in use.
    seq         The sequence number for this packet.
                This value is incremented for each
                successive packet transmitted for a session.
    auth_key    The shared SHA1 key for this packet.
    auth_hash   (Optional) The 20-byte SHA1 hash for the packet.
    auth_len    (Fixed) The length of the authentication section
                is 28 bytes.
    =========== ================================================
    """
    pass


bfd.set_classes(bfd._auth_parsers)
