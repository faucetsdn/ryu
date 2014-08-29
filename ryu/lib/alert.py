# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
from struct import calcsize


class SfTimeval32(object):
    _PACK_STR = '!II'
    _SIZE = 8

    def __init__(self, tv_sec, tv_usec):
        self.tv_sec = tv_sec
        self.tv_usec = tv_usec

    @classmethod
    def parser(cls, buf, offset):
        (tv_sec, tv_usec) = struct.unpack_from(
            cls._PACK_STR, buf, offset)

        msg = cls(tv_sec, tv_usec)

        return msg


class Event(object):
    _PACK_STR = '!IIIIIII'
    _SIZE = 36

    def __init__(self, sig_generator, sig_id, sig_rev, classification,
                 priority, event_id, event_reference, ref_time):
        self.sig_generator = sig_generator
        self.sig_id = sig_id
        self.sig_rev = sig_rev
        self.classification = classification
        self.priority = priority
        self.event_id = event_id
        self.event_reference = event_reference
        self.ref_time = ref_time

    @classmethod
    def parser(cls, buf, offset):
        (sig_generator, sig_id, sig_rev, classification, priority,
         event_id, event_reference) = struct.unpack_from(
             cls._PACK_STR, buf, offset)
        offset += calcsize(cls._PACK_STR)

        ref_time = SfTimeval32.parser(buf, offset)

        msg = cls(sig_generator, sig_id, sig_rev, classification,
                  priority, event_id, event_reference, ref_time)

        return msg


class PcapPktHdr32(object):
    _PACK_STR = '!II'
    _SIZE = 16

    def __init__(self, ts, caplen, len_):
        self.ts = ts
        self.caplen = caplen
        self.len = len_

    @classmethod
    def parser(cls, buf, offset):
        ts = SfTimeval32.parser(buf, offset)
        offset += SfTimeval32._SIZE

        (caplen, len_) = struct.unpack_from(
            cls._PACK_STR, buf, offset)

        msg = cls(ts, caplen, len_)

        return msg


class AlertPkt(object):
    _ALERTMSG_PACK_STR = '!256s'
    _ALERTPKT_PART_PACK_STR = '!IIIII65535s'
    _ALERTPKT_SIZE = 65863

    def __init__(self, alertmsg, pkth, dlthdr, nethdr, transhdr, data,
                 val, pkt, event):
        self.alertmsg = alertmsg
        self.pkth = pkth
        self.dlthdr = dlthdr
        self.nethdr = nethdr
        self.transhdr = transhdr
        self.data = data
        self.val = val
        self.pkt = pkt
        self.event = event

    @classmethod
    def parser(cls, buf):
        alertmsg = struct.unpack_from(cls._ALERTMSG_PACK_STR, buf)
        offset = calcsize(cls._ALERTMSG_PACK_STR)

        pkth = PcapPktHdr32.parser(buf, offset)
        offset += PcapPktHdr32._SIZE

        (dlthdr, nethdr, transhdr, data, val, pkt) = \
            struct.unpack_from(cls._ALERTPKT_PART_PACK_STR, buf,
                               offset)
        offset += calcsize(cls._ALERTPKT_PART_PACK_STR)

        event = Event.parser(buf, offset)

        msg = cls(alertmsg, pkth, dlthdr, nethdr, transhdr, data, val,
                  pkt, event)

        return msg
