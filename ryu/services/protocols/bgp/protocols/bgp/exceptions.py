import struct


class BgpExc(Exception):
    """Base bgp exception."""

    CODE = 0
    """BGP error code."""

    SUB_CODE = 0
    """BGP error sub-code."""

    SEND_ERROR = True
    """Flag if set indicates Notification message should be sent to peer."""

    def __init__(self, data=''):
        self.data = data

    def __str__(self):
        return '<%s %r>' % (self.__class__.__name__, self.data)


class BadNotification(BgpExc):
    SEND_ERROR = False

#=============================================================================
# Message Header Errors
#=============================================================================


class NotSync(BgpExc):
    CODE = 1
    SUB_CODE = 1


class BadLen(BgpExc):
    CODE = 1
    SUB_CODE = 2

    def __init__(self, msg_type_code, message_length):
        self.msg_type_code = msg_type_code
        self.length = message_length
        self.data = struct.pack('!H', self.length)

    def __str__(self):
        return '<BadLen %d msgtype=%d>' % (self.length, self.msg_type_code)


class BadMsg(BgpExc):
    """Error to indicate un-recognized message type.

    RFC says: If the Type field of the message header is not recognized, then
    the Error Subcode MUST be set to Bad Message Type.  The Data field MUST
    contain the erroneous Type field.
    """
    CODE = 1
    SUB_CODE = 3

    def __init__(self, msg_type):
        self.msg_type = msg_type
        self.data = struct.pack('B', msg_type)

    def __str__(self):
        return '<BadMsg %d>' % (self.msg,)

#=============================================================================
# OPEN Message Errors
#=============================================================================


class MalformedOptionalParam(BgpExc):
    """If recognized optional parameters are malformed.

    RFC says: If one of the Optional Parameters in the OPEN message is
    recognized, but is malformed, then the Error Subcode MUST be set to 0
    (Unspecific).
    """
    CODE = 2
    SUB_CODE = 0


class UnsupportedVersion(BgpExc):
    """Error to indicate unsupport bgp version number.

    RFC says: If the version number in the Version field of the received OPEN
    message is not supported, then the Error Subcode MUST be set to Unsupported
    Version Number.  The Data field is a 2-octet unsigned integer, which
    indicates the largest, locally-supported version number less than the
    version the remote BGP peer bid (as indicated in the received OPEN
    message), or if the smallest, locally-supported version number is greater
    than the version the remote BGP peer bid, then the smallest, locally-
    supported version number.
    """
    CODE = 2
    SUB_CODE = 1

    def __init__(self, locally_support_version):
        self.data = struct.pack('H', locally_support_version)


class BadPeerAs(BgpExc):
    """Error to indicate open message has incorrect AS number.

    RFC says: If the Autonomous System field of the OPEN message is
    unacceptable, then the Error Subcode MUST be set to Bad Peer AS.  The
    determination of acceptable Autonomous System numbers is configure peer AS.
    """
    CODE = 2
    SUB_CODE = 2


class BadBgpId(BgpExc):
    """Error to indicate incorrect BGP Identifier.

    RFC says: If the BGP Identifier field of the OPEN message is syntactically
    incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
    Syntactic correctness means that the BGP Identifier field represents a
    valid unicast IP host address.
    """
    CODE = 2
    SUB_CODE = 3


class UnsupportedOptParam(BgpExc):
    """Error to indicate unsupported optional parameters.

    RFC says: If one of the Optional Parameters in the OPEN message is not
    recognized, then the Error Subcode MUST be set to Unsupported Optional
    Parameters.
    """
    CODE = 2
    SUB_CODE = 4


class AuthFailure(BgpExc):
    CODE = 2
    SUB_CODE = 5


class UnacceptableHoldTime(BgpExc):
    """Error to indicate Unacceptable Hold Time in open message.

    RFC says: If the Hold Time field of the OPEN message is unacceptable, then
    the Error Subcode MUST be set to Unacceptable Hold Time.
    """
    CODE = 2
    SUB_CODE = 6

#=============================================================================
# UPDATE message related errors
#=============================================================================


class MalformedAttrList(BgpExc):
    """Error to indicate UPDATE message is malformed.

    RFC says: Error checking of an UPDATE message begins by examining the path
    attributes.  If the Withdrawn Routes Length or Total Attribute Length is
    too large (i.e., if Withdrawn Routes Length + Total Attribute Length + 23
    exceeds the message Length), then the Error Subcode MUST be set to
    Malformed Attribute List.
    """
    CODE = 3
    SUB_CODE = 1


class UnRegWellKnowAttr(BgpExc):
    CODE = 3
    SUB_CODE = 2


class MissingWellKnown(BgpExc):
    """Error to indicate missing well-known attribute.

    RFC says: If any of the well-known mandatory attributes are not present,
    then the Error Subcode MUST be set to Missing Well-known Attribute.  The
    Data field MUST contain the Attribute Type Code of the missing, well-known
    attribute.
    """
    CODE = 3
    SUB_CODE = 3

    def __init__(self, pattr_type_code):
        self.pattr_type_code = pattr_type_code
        self.data = struct.pack('B', pattr_type_code)


class AttrFlagError(BgpExc):
    """Error to indicate recognized path attributes have incorrect flags.

    RFC says: If any recognized attribute has Attribute Flags that conflict
    with the Attribute Type Code, then the Error Subcode MUST be set to
    Attribute Flags Error.  The Data field MUST contain the erroneous attribute
    (type, length, and value).
    """
    CODE = 3
    SUB_CODE = 4


class AttrLenError(BgpExc):
    CODE = 3
    SUB_CODE = 5


class InvalidOriginError(BgpExc):
    """Error indicates undefined Origin attribute value.

    RFC says: If the ORIGIN attribute has an undefined value, then the Error
    Sub- code MUST be set to Invalid Origin Attribute.  The Data field MUST
    contain the unrecognized attribute (type, length, and value).
    """
    CODE = 3
    SUB_CODE = 6


class RoutingLoop(BgpExc):
    CODE = 3
    SUB_CODE = 7


class InvalidNextHop(BgpExc):
    CODE = 3
    SUB_CODE = 8


class OptAttrError(BgpExc):
    """Error indicates Optional Attribute is malformed.

    RFC says: If an optional attribute is recognized, then the value of this
    attribute MUST be checked.  If an error is detected, the attribute MUST be
    discarded, and the Error Subcode MUST be set to Optional Attribute Error.
    The Data field MUST contain the attribute (type, length, and value).
    """
    CODE = 3
    SUB_CODE = 9


class InvalidNetworkField(BgpExc):
    CODE = 3
    SUB_CODE = 10


class MalformedAsPath(BgpExc):
    """Error to indicate if AP_PATH attribute is syntactically incorrect.

    RFC says: The AS_PATH attribute is checked for syntactic correctness.  If
    the path is syntactically incorrect, then the Error Subcode MUST be set to
    Malformed AS_PATH.
    """
    CODE = 3
    SUB_CODE = 11


#=============================================================================
# Hold Timer Expired
#=============================================================================


class HoldTimerExpired(BgpExc):
    """Error to indicate Hold Timer expired.

    RFC says: If a system does not receive successive KEEPALIVE, UPDATE, and/or
    NOTIFICATION messages within the period specified in the Hold Time field of
    the OPEN message, then the NOTIFICATION message with the Hold Timer Expired
    Error Code is sent and the BGP connection is closed.
    """
    CODE = 4
    SUB_CODE = 1

#=============================================================================
# Finite State Machine Error
#=============================================================================


class FiniteStateMachineError(BgpExc):
    """Error to indicate any Finite State Machine Error.

    RFC says: Any error detected by the BGP Finite State Machine (e.g., receipt
    of an unexpected event) is indicated by sending the NOTIFICATION message
    with the Error Code Finite State Machine Error.
    """
    CODE = 5
    SUB_CODE = 1


#=============================================================================
# Cease Errors
#=============================================================================

class MaxPrefixReached(BgpExc):
    CODE = 6
    SUB_CODE = 1


class AdminShutdown(BgpExc):
    """Error to indicate Administrative shutdown.

    RFC says: If a BGP speaker decides to administratively shut down its
    peering with a neighbor, then the speaker SHOULD send a NOTIFICATION
    message  with the Error Code Cease and the Error Subcode 'Administrative
    Shutdown'.
    """
    CODE = 6
    SUB_CODE = 2


class PeerDeConfig(BgpExc):
    CODE = 6
    SUB_CODE = 3


class AdminReset(BgpExc):
    CODE = 6
    SUB_CODE = 4


class ConnRejected(BgpExc):
    """Error to indicate Connection Rejected.

    RFC says: If a BGP speaker decides to disallow a BGP connection (e.g., the
    peer is not configured locally) after the speaker accepts a transport
    protocol connection, then the BGP speaker SHOULD send a NOTIFICATION
    message with the Error Code Cease and the Error Subcode "Connection
    Rejected".
    """
    CODE = 6
    SUB_CODE = 5


class OtherConfChange(BgpExc):
    CODE = 6
    SUB_CODE = 6


class CollisionResolution(BgpExc):
    """Error to indicate Connection Collision Resolution.

    RFC says: If a BGP speaker decides to send a NOTIFICATION message with the
    Error Code Cease as a result of the collision resolution procedure (as
    described in [BGP-4]), then the subcode SHOULD be set to "Connection
    Collision Resolution".
    """
    CODE = 6
    SUB_CODE = 7


class OutOfResource(BgpExc):
    CODE = 6
    SUB_CODE = 8
