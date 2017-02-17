# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

from __future__ import absolute_import

import logging

from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String

from ryu.lib import netdevice
from ryu.lib import ip
from ryu.lib.packet import zebra

from . import base


LOG = logging.getLogger(__name__)

# Default value for ethernet interface
DEFAULT_ETH_FLAGS = (
    netdevice.IFF_UP
    | netdevice.IFF_BROADCAST
    | netdevice.IFF_RUNNING
    | netdevice.IFF_MULTICAST)
DEFAULT_ETH_MTU = 1500


class Interface(base.Base):
    """
    Interface table for Zebra protocol service.

    The default value for each fields suppose "Loopback" interface.

    ``ifindex``: Number of index.

    ``ifname``: Name of this interface.

    ``status``: A combination of flags
    "ryu.lib.packet.zebra.ZEBRA_INTERFACE_*".
    The default value shows "active" and "link-detect".

    ``flags``: A combination of flags "ryu.lib.netdevice.IFF_*".
    The default value show "up", "loopback" and "running".

    ``metric``: Metric of this interface.

    ``ifmtu``: IPv4 MTU of this interface.

    ``ifmtu6``: IPv6 MTU of this interface.

    ``bandwidth``: Bandwidth of this interface.

    ``ll_type``: Link Layer Type.
    One of "ryu.lib.packet.zebra.ZEBRA_LLT_*" types.

    ``hw_addr``: Hardware address of this interface (mostly, MAC address).

    ``inet``: List of IPv4 addresses separated by a comma.
    (e.g., "192.168.1.100/24,192.168.2.100/24)".

    ``inet6``: List of IPv6 addresses separated by a comma.
    """
    __tablename__ = 'interface'

    ifindex = Column(Integer, primary_key=True)
    ifname = Column(String, default="lo")
    status = Column(
        Integer,
        default=(
            zebra.ZEBRA_INTERFACE_ACTIVE
            | zebra.ZEBRA_INTERFACE_LINKDETECTION))
    flags = Column(
        Integer,
        default=(
            netdevice.IFF_UP
            | netdevice.IFF_LOOPBACK
            | netdevice.IFF_RUNNING))
    metric = Column(Integer, default=1)
    ifmtu = Column(Integer, default=0x10000)
    ifmtu6 = Column(Integer, default=0x10000)
    bandwidth = Column(Integer, default=0)
    ll_type = Column(Integer, default=zebra.ZEBRA_LLT_ETHER)
    hw_addr = Column(String, default='00:00:00:00:00:00')
    # Note: Only the PostgreSQL backend has support sqlalchemy.ARRAY,
    # we use the comma separated string as array instead.
    inet = Column(String, default='')
    inet6 = Column(String, default='')


@base.sql_function
def ip_link_show(session, **kwargs):
    """
    Returns a first interface record matching the given filtering rules.

    The arguments for "kwargs" is the same with Interface class.

    :param session: Session instance connecting to database.
    :param kwargs: Filtering rules to query.
    :return: An instance of Interface record.
    """
    return session.query(Interface).filter_by(**kwargs).first()


@base.sql_function
def ip_link_show_all(session, **kwargs):
    """
    Returns all interface records matching the given filtering rules.

    The arguments for "kwargs" is the same with Interface class.

    :param session: Session instance connecting to database.
    :param kwargs: Filtering rules to query.
    :return: A list of Interface records.
    """
    return session.query(Interface).filter_by(**kwargs).all()


@base.sql_function
def ip_link_add(session, name, type_='loopback', lladdr='00:00:00:00:00:00'):
    """
    Adds an interface record into Zebra protocol service database.

    The arguments are similar to "ip link add" command of iproute2.

    :param session: Session instance connecting to database.
    :param name: Name of interface.
    :param type_: Type of interface. 'loopback' or 'ethernet'.
    :param lladdr: Link layer address. Mostly MAC address.
    :return: Instance of added record or already existing record.
    """
    intf = ip_link_show(session, ifname=name)
    if intf:
        LOG.debug('Interface "%s" already exists: %s', intf.ifname, intf)
        return intf

    if type_ == 'ethernet':
        intf = Interface(
            ifname=name,
            flags=DEFAULT_ETH_FLAGS,
            ifmtu=DEFAULT_ETH_MTU,
            ifmtu6=DEFAULT_ETH_MTU,
            hw_addr=lladdr)
    else:  # type_ == 'loopback':
        intf = Interface(
            ifname=name,
            inet='127.0.0.1/8',
            inet6='::1/128')

    session.add(intf)

    return intf


@base.sql_function
def ip_link_delete(session, name):
    """
    Deletes an interface record from Zebra protocol service database.

    The arguments are similar to "ip link delete" command of iproute2.

    :param session: Session instance connecting to database.
    :param name: Name of interface.
    :return: Name of interface which was deleted. None if failed.
    """
    intf = ip_link_show(session, ifname=name)
    if not intf:
        LOG.debug('Interface "%s" does not exist', name)
        return None

    session.delete(intf)

    return name


# Currently, functions corresponding to "ip link show" and "ip address show"
# have the same implementation.
ip_address_show = ip_link_show
ip_address_show_all = ip_link_show_all


@base.sql_function
def ip_address_add(session, ifname, ifaddr):
    """
    Adds an IP address to interface record identified with the given "ifname".

    The arguments are similar to "ip address add" command of iproute2.

    :param session: Session instance connecting to database.
    :param ifname: Name of interface.
    :param ifaddr: IPv4 or IPv6 address.
    :return: Instance of record or "None" if failed.
    """
    def _append_inet_addr(intf_inet, addr):
        addr_list = intf_inet.split(',')
        if addr in addr_list:
            LOG.debug(
                'Interface "%s" has already "ifaddr": %s',
                intf.ifname, addr)
            return intf_inet
        else:
            addr_list.append(addr)
            return ','.join(addr_list)

    intf = ip_link_show(session, ifname=ifname)
    if not intf:
        LOG.debug('Interface "%s" does not exist', ifname)
        return None

    if ip.valid_ipv4(ifaddr):
        intf.inet = _append_inet_addr(intf.inet, ifaddr)
    elif ip.valid_ipv6(ifaddr):
        intf.inet6 = _append_inet_addr(intf.inet6, ifaddr)
    else:
        LOG.debug('Invalid IP address for "ifaddr": %s', ifaddr)
        return None

    return intf


@base.sql_function
def ip_address_delete(session, ifname, ifaddr):
    """
    Deletes an IP address from interface record identified with the given
    "ifname".

    The arguments are similar to "ip address delete" command of iproute2.

    :param session: Session instance connecting to database.
    :param ifname: Name of interface.
    :param ifaddr: IPv4 or IPv6 address.
    :return: Instance of record or "None" if failed.
    """
    def _remove_inet_addr(intf_inet, addr):
        addr_list = intf_inet.split(',')
        if addr not in addr_list:
            LOG.debug(
                'Interface "%s" does not have "ifaddr": %s',
                intf.ifname, addr)
            return intf_inet
        else:
            addr_list.remove(addr)
            return ','.join(addr_list)

    intf = ip_link_show(session, ifname=ifname)
    if not intf:
        LOG.debug('Interface "%s" does not exist', ifname)
        return None

    if ip.valid_ipv4(ifaddr):
        intf.inet = _remove_inet_addr(intf.inet, ifaddr)
    elif ip.valid_ipv6(ifaddr):
        intf.inet6 = _remove_inet_addr(intf.inet6, ifaddr)
    else:
        LOG.debug('Invalid IP address for "ifaddr": %s', ifaddr)
        return None

    return intf
