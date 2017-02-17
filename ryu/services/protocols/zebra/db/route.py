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
import socket

import netaddr
from sqlalchemy import Column
from sqlalchemy import Boolean
from sqlalchemy import Integer
from sqlalchemy import String

from ryu.lib.packet import safi as packet_safi
from ryu.lib.packet import zebra

from . import base
from . import interface


LOG = logging.getLogger(__name__)


class Route(base.Base):
    """
    Route table (like routing table) for Zebra protocol service.

    ``id``: (Primary Key) ID of this route.

    ``family``: Address Family, not AFI (Address Family Identifiers).
    Mostly, "socket.AF_INET" or "socket.AF_INET6".

    ``safi``: Subsequent Address Family Identifiers.

    ``destination``: Destination prefix of this route.

    ``gateway``: Next hop address of this route.
    The default is "" (empty string).

    ``ifindex``: Index of interface to forward packets.

    ``source``: Source IP address of this route, which should be an
     address assigned to the local interface.

    ``route_type``: Route Type of this route.
    This type shows which daemon (or kernel) generated this route.

    ``is_selected``: Whether this route is selected for "destination".
    """
    __tablename__ = 'route'

    id = Column(Integer, primary_key=True)
    family = Column(Integer, default=socket.AF_INET)
    safi = Column(Integer, default=packet_safi.UNICAST)
    destination = Column(String, default='0.0.0.0/0')
    gateway = Column(String, default='')
    ifindex = Column(Integer, default=0)
    source = Column(String, default='')
    route_type = Column(Integer, default=zebra.ZEBRA_ROUTE_KERNEL)
    is_selected = Column(Boolean, default=False)


@base.sql_function
def ip_route_show(session, destination, device, **kwargs):
    """
    Returns a selected route record matching the given filtering rules.

    The arguments are similar to "ip route showdump" command of iproute2.

    :param session: Session instance connecting to database.
    :param destination: Destination prefix.
    :param device: Source device.
    :param kwargs: Filtering rules to query.
    :return: Instance of route record or "None" if failed.
    """
    intf = interface.ip_link_show(session, ifname=device)
    if not intf:
        LOG.debug('Interface "%s" does not exist', device)
        return None

    return session.query(Route).filter_by(
        destination=destination, ifindex=intf.ifindex, **kwargs).first()


@base.sql_function
def ip_route_show_all(session, **kwargs):
    """
    Returns a selected route record matching the given filtering rules.

    The arguments are similar to "ip route showdump" command of iproute2.

    If "is_selected=True", disables the existing selected route for the
    given destination.

    :param session: Session instance connecting to database.
    :param kwargs: Filtering rules to query.
    :return: A list of route records.
    """
    return session.query(Route).filter_by(**kwargs).all()


@base.sql_function
def ip_route_add(session, destination, device=None, gateway='', source='',
                 ifindex=0, route_type=zebra.ZEBRA_ROUTE_KERNEL,
                 is_selected=True):
    """
    Adds a route record into Zebra protocol service database.

    The arguments are similar to "ip route add" command of iproute2.

    If "is_selected=True", disables the existing selected route for the
    given destination.

    :param session: Session instance connecting to database.
    :param destination: Destination prefix.
    :param device: Source device.
    :param gateway: Gateway IP address.
    :param source: Source IP address.
    :param ifindex: Index of source device.
    :param route_type: Route type of daemon (or kernel).
    :param is_selected: If select the given route as "in use" or not.
    :return: Instance of record or "None" if failed.
    """
    if device:
        intf = interface.ip_link_show(session, ifname=device)
        if not intf:
            LOG.debug('Interface "%s" does not exist', device)
            return None
        ifindex = ifindex or intf.ifindex

        route = ip_route_show(session, destination=destination, device=device)
        if route:
            LOG.debug(
                'Route to "%s" already exists on "%s" device',
                destination, device)
            return route

    dest_addr, dest_prefix_num = destination.split('/')
    dest_prefix_num = int(dest_prefix_num)
    if netaddr.valid_ipv4(dest_addr) and 0 <= dest_prefix_num <= 32:
        family = socket.AF_INET
    elif netaddr.valid_ipv6(dest_addr) and 0 <= dest_prefix_num <= 128:
        family = socket.AF_INET6
    else:
        LOG.debug('Invalid IP address for "prefix": %s', destination)
        return None
    safi = packet_safi.UNICAST

    if is_selected:
        old_routes = ip_route_show_all(
            session, destination=destination, is_selected=True)
        for old_route in old_routes:
            if old_route:
                LOG.debug('Set existing route to unselected: %s', old_route)
                old_route.is_selected = False

    new_route = Route(
        family=family,
        safi=safi,
        destination=destination,
        gateway=gateway,
        ifindex=ifindex,
        source=source,
        route_type=route_type,
        is_selected=is_selected)

    session.add(new_route)

    return new_route


@base.sql_function
def ip_route_delete(session, destination, **kwargs):
    """
    Deletes route record(s) from Zebra protocol service database.

    The arguments are similar to "ip route delete" command of iproute2.

    :param session: Session instance connecting to database.
    :param destination: Destination prefix.
    :param kwargs: Filtering rules to query.
    :return: Records which are deleted.
    """
    routes = ip_route_show_all(session, destination=destination, **kwargs)
    for route in routes:
        session.delete(route)

    return routes
