# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import netaddr


class AddressConverter(object):
    def __init__(self, addr, strat, **kwargs):
        self._addr = addr
        self._strat = strat
        self._addr_kwargs = kwargs

    def text_to_bin(self, text):
        return self._addr(text, **self._addr_kwargs).packed

    def bin_to_text(self, bin):
        return str(self._addr(self._strat.packed_to_int(bin),
                              **self._addr_kwargs))

ipv4 = AddressConverter(netaddr.IPAddress, netaddr.strategy.ipv4, version=4)
ipv6 = AddressConverter(netaddr.IPAddress, netaddr.strategy.ipv6, version=6)


class mac_mydialect(netaddr.mac_unix):
    word_fmt = '%.2x'
mac = AddressConverter(netaddr.EUI, netaddr.strategy.eui48, version=48,
                       dialect=mac_mydialect)
