# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
 Module provides utilities for validation.
"""
import numbers
import re
import socket

from ryu.lib import ip


def is_valid_mac(mac):
    """Returns True if the given MAC address is valid.

    The given MAC address should be a colon hexadecimal notation string.

    Samples:
        - valid address: aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66
        - invalid address: aa:bb:cc:dd, 11-22-33-44-55-66, etc.
    """
    return bool(re.match(r'^' + r'[\:\-]'.join([r'([0-9a-f]{2})'] * 6)
                         + r'$', mac.lower()))


def is_valid_ip_prefix(prefix, bits):
    """Returns True if *prefix* is a valid IPv4 or IPv6 address prefix.

    *prefix* should be a number between 0 to *bits* length.
    """
    try:
        # Prefix should be a number
        prefix = int(prefix)
    except ValueError:
        return False

    # Prefix should be a number between 0 to *bits*
    return 0 <= prefix <= bits


def is_valid_ipv4(ipv4):
    """Returns True if given is a valid ipv4 address.

    Given value should be a dot-decimal notation string.

    Samples:
        - valid address: 10.0.0.1, 192.168.0.1
        - invalid address: 11.0.0, 192:168:0:1, etc.
    """
    return ip.valid_ipv4(ipv4)


def is_valid_ipv4_prefix(ipv4_prefix):
    """Returns True if *ipv4_prefix* is a valid prefix with mask.

    Samples:
        - valid prefix: 1.1.1.0/32, 244.244.244.1/10
        - invalid prefix: 255.2.2.2/2, 2.2.2/22, etc.
    """
    if not isinstance(ipv4_prefix, str):
        return False

    tokens = ipv4_prefix.split('/')
    if len(tokens) != 2:
        return False

    # Validate address/mask and return
    return is_valid_ipv4(tokens[0]) and is_valid_ip_prefix(tokens[1], 32)


def is_valid_ipv6(ipv6):
    """Returns True if given `ipv6` is a valid IPv6 address
    """
    return ip.valid_ipv6(ipv6)


def is_valid_ipv6_prefix(ipv6_prefix):
    """Returns True if given `ipv6_prefix` is a valid IPv6 prefix."""

    # Validate input type
    if not isinstance(ipv6_prefix, str):
        return False

    tokens = ipv6_prefix.split('/')
    if len(tokens) != 2:
        return False

    # Validate address/mask and return
    return is_valid_ipv6(tokens[0]) and is_valid_ip_prefix(tokens[1], 128)


def is_valid_old_asn(asn):
    """Returns True if the given AS number is Two Octet."""
    return isinstance(asn, numbers.Integral) and 0 <= asn <= 0xffff


def is_valid_asn(asn):
    """Returns True if the given AS number is Two or Four Octet."""
    return isinstance(asn, numbers.Integral) and 0 <= asn <= 0xffffffff


def is_valid_vpnv4_prefix(prefix):
    """Returns True if given prefix is a string represent vpnv4 prefix.

    Vpnv4 prefix is made up of RD:Ipv4, where RD is represents route
    distinguisher and Ipv4 represents valid dot-decimal ipv4 notation string.
    """
    if not isinstance(prefix, str):
        return False

    # Split the prefix into route distinguisher and IP
    tokens = prefix.split(':', 2)
    if len(tokens) != 3:
        return False

    # Validate route distinguisher
    if not is_valid_route_dist(':'.join([tokens[0], tokens[1]])):
        return False

    # Validate IPv4 prefix and return
    return is_valid_ipv4_prefix(tokens[2])


def is_valid_vpnv6_prefix(prefix):
    """Returns True if given prefix is a string represent vpnv6 prefix.

    Vpnv6 prefix is made up of RD:Ipv6, where RD is represents route
    distinguisher and Ipv6 represents valid colon hexadecimal notation string.
    """
    if not isinstance(prefix, str):
        return False

    # Split the prefix into route distinguisher and IP
    tokens = prefix.split(':', 2)
    if len(tokens) != 3:
        return False

    # Validate route distinguisher
    if not is_valid_route_dist(':'.join([tokens[0], tokens[1]])):
        return False

    # Validate IPv6 prefix and return
    return is_valid_ipv6_prefix(tokens[2])


def is_valid_med(med):
    """Returns True if value of *med* is valid as per RFC.

    According to RFC MED is a four octet non-negative integer and
    value '((2 ** 32) - 1) =  0xffffffff' denotes an "infinity" metric.
    """
    return isinstance(med, numbers.Integral) and 0 <= med <= 0xffffffff


def is_valid_mpls_label(label):
    """Validates `label` according to MPLS label rules

    RFC says:
    This 20-bit field.
    A value of 0 represents the "IPv4 Explicit NULL Label".
    A value of 1 represents the "Router Alert Label".
    A value of 2 represents the "IPv6 Explicit NULL Label".
    A value of 3 represents the "Implicit NULL Label".
    Values 4-15 are reserved.
    """
    if (not isinstance(label, numbers.Integral) or
            (4 <= label <= 15) or
            (label < 0 or label > 2 ** 20)):
        return False

    return True


def is_valid_mpls_labels(labels):
    """Returns True if the given value is a list of valid MPLS labels.
    """
    if not isinstance(labels, (list, tuple)):
        return False

    for label in labels:
        if not is_valid_mpls_label(label):
            return False

    return True


def is_valid_route_dist(route_dist):
    """Validates *route_dist* as string representation of route distinguisher.

    Returns True if *route_dist* is as per our convention of RD, else False.
    Our convention is to represent RD as a string in format:
    *admin_sub_field:assigned_num_field* and *admin_sub_field* can be valid
    IPv4 string representation.
    Valid examples: '65000:222', '1.2.3.4:4432'.
    Invalid examples: '1.11.1: 333'
    """
    # TODO(PH): Provide complete implementation.
    return is_valid_ext_comm_attr(route_dist)


def is_valid_ext_comm_attr(attr):
    """Validates *attr* as string representation of RT or SOO.

    Returns True if *attr* is as per our convention of RT or SOO, else
    False. Our convention is to represent RT/SOO is a string with format:
    *global_admin_part:local_admin_path*
    """
    if not isinstance(attr, str):
        return False

    tokens = attr.rsplit(':', 1)
    if len(tokens) != 2:
        return False

    try:
        if '.' in tokens[0]:
            if not is_valid_ipv4(tokens[0]):
                return False
        else:
            int(tokens[0])
        int(tokens[1])
    except (ValueError, socket.error):
        return False

    return True


def is_valid_esi(esi):
    """Returns True if the given EVPN Ethernet SegmentEthernet ID is valid."""
    if isinstance(esi, numbers.Integral):
        return 0 <= esi <= 0xffffffffffffffffff
    return isinstance(esi, dict)


def is_valid_ethernet_tag_id(etag_id):
    """Returns True if the given EVPN Ethernet Tag ID is valid.

    Ethernet Tag ID should be a 32-bit field number.
    """
    return isinstance(etag_id, numbers.Integral) and 0 <= etag_id <= 0xffffffff


def is_valid_vni(vni):
    """Returns True if the given Virtual Network Identifier for VXLAN
    is valid.

    Virtual Network Identifier should be a 24-bit field number.
    """
    return isinstance(vni, numbers.Integral) and 0 <= vni <= 0xffffff
