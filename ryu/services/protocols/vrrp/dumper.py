# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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
VRRP event dumper
This is also a template for router implementation that support VRRP
"""

from ryu.base import app_manager
from ryu.controller import handler
from ryu.services.protocols.vrrp import event as vrrp_event


class VRRPDumper(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(VRRPDumper, self).__init__(*args, **kwargs)

    @handler.set_ev_cls(vrrp_event.EventVRRPStateChanged)
    def vrrp_state_changed_handler(self, ev):
        old_state = ev.old_state
        new_state = ev.new_state
        self.logger.info('state change %s: %s -> %s', ev.instance_name,
                         old_state, new_state)
        if new_state == vrrp_event.VRRP_STATE_MASTER:
            self.logger.info('becomes master')
            if old_state is None:
                # RFC3768 6.4.1
                # o  Broadcast a gratuitous ARP request containing the virtual
                # router MAC address for each IP address associated with the
                # virtual router.
                #
                # or
                #
                # RFC 5795 6.4.1
                # (115)+ If the protected IPvX address is an IPv4 address,
                # then:
                #   (120) * Broadcast a gratuitous ARP request containing the
                #   virtual router MAC address for each IP address associated
                #   with the virtual router.
                # (125) + else // IPv6
                #   (130) * For each IPv6 address associated with the virtual
                #   router, send an unsolicited ND Neighbor Advertisement with
                #   the Router Flag (R) set, the Solicited Flag (S) unset, the
                #   Override flag (O) set, the target address set to the IPv6
                #   address of the virtual router, and the target link-layer
                #   address set to the virtual router MAC address.
                #
                pass
            elif old_state == vrrp_event.VRRP_STATE_BACKUP:
                # RFC3768 6.4.2
                # o  Broadcast a gratuitous ARP request containing the virtual
                #    router MAC address for each IP address associated with the
                #    virtual router
                #
                # or
                #
                # RFC 5795 6.4.2
                # (375)+ If the protected IPvX address is an IPv4 address,
                # then:
                #   (380)* Broadcast a gratuitous ARP request on that interface
                #   containing the virtual router MAC address for each IPv4
                #   address associated with the virtual router.
                # (385) + else // ipv6
                #   (390) * Compute and join the Solicited-Node multicast
                #   address [RFC4291] for the IPv6 address(es) associated with
                #   the virtual router.
                #   (395) * For each IPv6 address associated with the virtual
                #   router, send an unsolicited ND Neighbor Advertisement with
                #   the Router Flag (R) set, the Solicited Flag (S) unset, the
                #   Override flag (O) set, the target address set to the IPv6
                #   address of the virtual router, and the target link-layer
                #   address set to the virtual router MAC address.
                pass

            # RFC 3768 6.4.3
            # -  MUST respond to ARP requests for the IP address(es) associated
            #    with the virtual router.
            # -  MUST forward packets with a destination link layer MAC address
            #    equal to the virtual router MAC address.
            # -  MUST NOT accept packets addressed to the IP address(es)
            #    associated with the virtual router if it is not the IP address
            #    owner.
            # -  MUST accept packets addressed to the IP address(es) associated
            #    with the virtual router if it is the IP address owner.
            #
            # or
            #
            # RFC5798 6.4.3
            # (605) - If the protected IPvX address is an IPv4 address, then:
            #   (610) + MUST respond to ARP requests for the IPv4 address(es)
            #   associated with the virtual router.
            # (615) - else // ipv6
            #   (620) + MUST be a member of the Solicited-Node multicast
            #   address for the IPv6 address(es) associated with the virtual
            #   router.
            #   (625) + MUST respond to ND Neighbor Solicitation message for
            #   the IPv6 address(es) associated with the virtual router.
            #   (630) ++ MUST send ND Router Advertisements for the virtual
            #   router.
            #   (635) ++ If Accept_Mode is False:  MUST NOT drop IPv6 Neighbor
            #   Solicitations and Neighbor Advertisements.
            # (640) +-endif // ipv4?
            # (645) - MUST forward packets with a destination link-layer MAC
            # address equal to the virtual router MAC address.
            # (650) - MUST accept packets addressed to the IPvX address(es)
            # associated with the virtual router if it is the IPvX address
            # owner or if Accept_Mode is True.  Otherwise, MUST NOT accept
            # these packets.

        elif new_state == vrrp_event.VRRP_STATE_BACKUP:
            self.logger.info('becomes backup')

            # RFC 3768 6.4.2 Backup
            # -  MUST NOT respond to ARP requests for the IP address(s)
            #    associated with the virtual router.
            # -  MUST discard packets with a destination link layer MAC address
            #    equal to the virtual router MAC address.
            # -  MUST NOT accept packets addressed to the IP address(es)
            #    associated with the virtual router.
            #
            # or
            #
            # RFC 5798 6.4.2 Backup
            # (305) - If the protected IPvX address is an IPv4 address, then:
            #   (310) + MUST NOT respond to ARP requests for the IPv4
            #   address(es) associated with the virtual router.
            # (315) - else // protected addr is IPv6
            #   (320) + MUST NOT respond to ND Neighbor Solicitation messages
            #   for the IPv6 address(es) associated with the virtual router.
            #   (325) + MUST NOT send ND Router Advertisement messages for the
            #   virtual router.
            # (330) -endif // was protected addr IPv4?
            # (335) - MUST discard packets with a destination link-layer MAC
            # address equal to the virtual router MAC address.
            # (340) - MUST NOT accept packets addressed to the IPvX address(es)
            # associated with the virtual router.
        elif new_state == vrrp_event.VRRP_STATE_INITIALIZE:
            if old_state is None:
                self.logger.info('initialized')
            else:
                self.logger.info('shutdowned')
        else:
            raise ValueError('invalid vrrp state %s' % new_state)
