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
import socket


def is_valid_ipv4(ipv4):
    """Returns True if given is a valid ipv4 address.

    Given value should be a dot-decimal notation string.
    """
    valid = True

    if not isinstance(ipv4, str):
        valid = False
    else:
        try:
            a, b, c, d = [int(x) for x in ipv4.split('.')]
            if (a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or c > 255 or
                    d < 0 or d > 255):
                valid = False
        except ValueError:
            valid = False

    return valid


def is_valid_ipv4_prefix(ipv4_prefix):
    """Returns True if *ipv4_prefix* is a valid prefix with mask.

    Samples:
        - valid prefix: 1.1.1.0/32, 244.244.244.1/10
        - invalid prefix: 255.2.2.2/2, 2.2.2/22, etc.
    """
    if not isinstance(ipv4_prefix, str):
        return False

    valid = True
    tokens = ipv4_prefix.split('/')
    if len(tokens) != 2:
        valid = False
    else:
        if not is_valid_ipv4(tokens[0]):
            valid = False
        else:
            # Validate mask
            try:
                # Mask is a number
                mask = int(tokens[1])
                # Mask is number between 0 to 32
                if mask < 0 or mask > 32:
                    valid = False
            except ValueError:
                valid = False

    return valid


def is_valid_ipv6(ipv6):
    """Returns True if given `ipv6` is a valid IPv6 address

    Uses `socket.inet_pton` to determine validity.
    """
    valid = True
    try:
        socket.inet_pton(socket.AF_INET6, ipv6)
    except socket.error:
        valid = False

    return valid


def is_valid_ipv6_prefix(ipv6_prefix):
    """Returns True if given `ipv6_prefix` is a valid IPv6 prefix."""

    # Validate input type
    if not isinstance(ipv6_prefix, str):
        return False

    valid = True
    tokens = ipv6_prefix.split('/')
    if len(tokens) != 2:
        valid = False
    else:
        if not is_valid_ipv6(tokens[0]):
            valid = False
        else:
            # Validate mask
            try:
                # Mask is a number
                mask = int(tokens[1])
                # Mask is number between 0 to 128
                if mask < 0 or mask > 128:
                    valid = False
            except ValueError:
                valid = False

    return valid


def is_valid_old_asn(asn):
    """Returns true if given asn is a 16 bit number.

    Old AS numbers are 16 but unsigned number.
    """
    valid = True
    # AS number should be a 16 bit number
    if (not isinstance(asn, numbers.Integral) or (asn < 0) or
            (asn > ((2 ** 16) - 1))):
        valid = False

    return valid


def is_valid_vpnv4_prefix(prefix):
    """Returns True if given prefix is a string represent vpnv4 prefix.

    Vpnv4 prefix is made up of RD:Ipv4, where RD is represents route
    distinguisher and Ipv4 represents valid dot-decimal ipv4 notation string.
    """
    valid = True

    if not isinstance(prefix, str):
        valid = False
    else:
        # Split the prefix into route distinguisher and IP
        tokens = prefix.split(':')
        if len(tokens) != 3:
            valid = False
        else:
            # Check if first two tokens can form a valid RD
            try:
                # admin_subfield
                int(tokens[0])
                # assigned_subfield
                int(tokens[1])
            except ValueError:
                valid = False

            # Check if ip part is valid
            valid = is_valid_ipv4_prefix(tokens[2])

    return valid


def is_valid_med(med):
    """Returns True if value of *med* is valid as per RFC.

    According to RFC MED is a four octet non-negative integer.
    """
    valid = True

    if not isinstance(med, numbers.Integral):
        valid = False
    else:
        if med < 0 or med > (2 ** 32) - 1:
            valid = False

    return valid


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
    valid = True

    if (not isinstance(label, numbers.Integral) or
            (label >= 4 and label <= 15) or
            (label < 0 or label > 2 ** 20)):
        valid = False

    return valid


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
    is_valid = True

    if not isinstance(attr, str):
        is_valid = False
    else:
        first, second = attr.split(':')
        try:
            if '.' in first:
                socket.inet_aton(first)
            else:
                int(first)
                int(second)
        except (ValueError, socket.error):
            is_valid = False

    return is_valid
