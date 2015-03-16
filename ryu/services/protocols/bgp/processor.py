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
 Module related to processing bgp paths.
"""

import logging

from ryu.services.protocols.bgp.base import Activity
from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import BGP_PROCESSOR_ERROR_CODE
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.utils import circlist
from ryu.services.protocols.bgp.utils.evtlet import EventletIOFactory

from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_LOCAL_PREF
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MULTI_EXIT_DISC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_IGP
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_EGP
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_INCOMPLETE

LOG = logging.getLogger('bgpspeaker.processor')


@add_bgp_error_metadata(code=BGP_PROCESSOR_ERROR_CODE, sub_code=1,
                        def_desc='Error occurred when processing bgp '
                        'destination.')
class BgpProcessorError(BGPSException):
    """Base exception related to all destination path processing errors.
    """
    pass


# Disabling known bug in pylint.
# pylint: disable=R0921
class BgpProcessor(Activity):
    """Worker that processes queued `Destination'.

    `Destination` that have updates related to its paths need to be
    (re)processed. Only one instance of this processor is enough for normal
    cases. If you want more control on which destinations get processed faster
    compared to other destinations, you can create several instance of this
    works to achieve the desired work flow.
    """

    # Max. number of destinations processed per cycle.
    MAX_DEST_PROCESSED_PER_CYCLE = 100

    #
    # DestQueue
    #
    # A circular list type in which objects are linked to each
    # other using the 'next_dest_to_process' and 'prev_dest_to_process'
    # attributes.
    #
    _DestQueue = circlist.CircularListType(
        next_attr_name='next_dest_to_process',
        prev_attr_name='prev_dest_to_process')

    def __init__(self, core_service, work_units_per_cycle=None):
        Activity.__init__(self)
        # Back pointer to core service instance that created this processor.
        self._core_service = core_service
        self._dest_queue = BgpProcessor._DestQueue()
        self._rtdest_queue = BgpProcessor._DestQueue()
        self.dest_que_evt = EventletIOFactory.create_custom_event()
        self.work_units_per_cycle =\
            work_units_per_cycle or BgpProcessor.MAX_DEST_PROCESSED_PER_CYCLE

    def _run(self, *args, **kwargs):
        # Sit in tight loop, getting destinations from the queue and processing
        # one at a time.
        while True:
            LOG.debug('Starting new processing run...')
            # We process all RT destination first so that we get a new RT
            # filter that apply for each peer
            self._process_rtdest()

            # We then process a batch of other destinations (we do not process
            # all destination here as we want to give change to other
            # greenthread to run)
            self._process_dest()

            if self._dest_queue.is_empty():
                # If we have no destinations queued for processing, we wait.
                self.dest_que_evt.clear()
                self.dest_que_evt.wait()
            else:
                self.pause(0)

    def _process_dest(self):
        dest_processed = 0
        LOG.debug('Processing destination...')
        while (dest_processed < self.work_units_per_cycle and
                not self._dest_queue.is_empty()):
            # We process the first destination in the queue.
            next_dest = self._dest_queue.pop_first()
            if next_dest:
                next_dest.process()
                dest_processed += 1

    def _process_rtdest(self):
        LOG.debug('Processing RT NLRI destination...')
        if self._rtdest_queue.is_empty():
            return
        else:
            processed_any = False
            while not self._rtdest_queue.is_empty():
                # We process the first destination in the queue.
                next_dest = self._rtdest_queue.pop_first()
                if next_dest:
                    next_dest.process()
                    processed_any = True

            if processed_any:
                # Since RT destination were updated we update RT filters
                self._core_service.update_rtfilters()

    def enqueue(self, destination):
        """Enqueues given destination for processing.

        Given instance should be a valid destination.
        """
        if not destination:
            raise BgpProcessorError('Invalid destination %s.' % destination)

        dest_queue = self._dest_queue
        # RtDest are queued in a separate queue
        if destination.route_family == RF_RTC_UC:
            dest_queue = self._rtdest_queue

        # We do not add given destination to the queue for processing if
        # it is already on the queue.
        if not dest_queue.is_on_list(destination):
            dest_queue.append(destination)

        # Wake-up processing thread if sleeping.
        self.dest_que_evt.set()

# =============================================================================
# Best path computation related utilities.
# =============================================================================

# Various reasons a path is chosen as best path.
BPR_UNKNOWN = 'Unknown'
BPR_ONLY_PATH = 'Only Path'
BPR_REACHABLE_NEXT_HOP = 'Reachable Next Hop'
BPR_HIGHEST_WEIGHT = 'Highest Weight'
BPR_LOCAL_PREF = 'Local Pref'
BPR_LOCAL_ORIGIN = 'Local Origin'
BPR_ASPATH = 'AS Path'
BPR_ORIGIN = 'Origin'
BPR_MED = 'MED'
BPR_ASN = 'ASN'
BPR_IGP_COST = 'IGP Cost'
BPR_ROUTER_ID = 'Router ID'


def _compare_by_version(path1, path2):
    """Returns the current/latest learned path.

    Checks if given paths are from same source/peer and then compares their
    version number to determine which path is received later. If paths are from
    different source/peer return None.
    """
    if path1.source == path2.source:
        if path1.source_version_num > path2.source_version_num:
            return path1
        else:
            return path2
    return None


def compute_best_path(local_asn, path1, path2):
    """Compares given paths and returns best path.

    Parameters:
        -`local_asn`: asn of local bgpspeaker
        -`path1`: first path to compare
        -`path2`: second path to compare

    Best path processing will involve following steps:
    1.  Select a path with a reachable next hop.
    2.  Select the path with the highest weight.
    3.  If path weights are the same, select the path with the highest
        local preference value.
    4.  Prefer locally originated routes (network routes, redistributed
        routes, or aggregated routes) over received routes.
    5.  Select the route with the shortest AS-path length.
    6.  If all paths have the same AS-path length, select the path based
        on origin: IGP is preferred over EGP; EGP is preferred over
        Incomplete.
    7.  If the origins are the same, select the path with lowest MED
        value.
    8.  If the paths have the same MED values, select the path learned
        via EBGP over one learned via IBGP.
    9.  Select the route with the lowest IGP cost to the next hop.
    10. Select the route received from the peer with the lowest BGP
        router ID.

    Returns None if best-path among given paths cannot be computed else best
    path.
    Assumes paths from NC has source equal to None.
    """
    best_path = None
    best_path_reason = BPR_UNKNOWN

    # Follow best path calculation algorithm steps.
    if best_path is None:
        best_path = _cmp_by_reachable_nh(path1, path2)
        best_path_reason = BPR_REACHABLE_NEXT_HOP
    if best_path is None:
        best_path = _cmp_by_higest_wg(path1, path2)
        best_path_reason = BPR_HIGHEST_WEIGHT
    if best_path is None:
        best_path = _cmp_by_local_pref(path1, path2)
        best_path_reason = BPR_LOCAL_PREF
    if best_path is None:
        best_path = _cmp_by_local_origin(path1, path2)
        best_path_reason = BPR_LOCAL_ORIGIN
    if best_path is None:
        best_path = _cmp_by_aspath(path1, path2)
        best_path_reason = BPR_ASPATH
    if best_path is None:
        best_path = _cmp_by_origin(path1, path2)
        best_path_reason = BPR_ORIGIN
    if best_path is None:
        best_path = _cmp_by_med(path1, path2)
        best_path_reason = BPR_MED
    if best_path is None:
        best_path = _cmp_by_asn(local_asn, path1, path2)
        best_path_reason = BPR_ASN
    if best_path is None:
        best_path = _cmp_by_igp_cost(path1, path2)
        best_path_reason = BPR_IGP_COST
    if best_path is None:
        best_path = _cmp_by_router_id(local_asn, path1, path2)
        best_path_reason = BPR_ROUTER_ID
    if best_path is None:
        best_path_reason = BPR_UNKNOWN

    return (best_path, best_path_reason)


def _cmp_by_reachable_nh(path1, path2):
    """Compares given paths and selects best path based on reachable next-hop.

    If no path matches this criteria, return None.
    """
    # TODO(PH): Currently we do not have a way to check if a IGP route to
    # NEXT_HOP exists from BGPS.
    return None


def _cmp_by_higest_wg(path1, path2):
    """Selects a path with highest weight.

    Weight is BGPS specific parameter. It is local to the router on which it
     is configured.
    Return:
        None if best path among given paths cannot be decided, else best path.
    """
    # TODO(PH): Revisit this when BGPS has concept of policy to be applied to
    # in-bound NLRIs.
    return None


def _cmp_by_local_pref(path1, path2):
    """Selects a path with highest local-preference.

    Unlike the weight attribute, which is only relevant to the local
    router, local preference is an attribute that routers exchange in the
    same AS. Highest local-pref is preferred. If we cannot decide,
    we return None.
    """
    # TODO(PH): Revisit this when BGPS has concept of policy to be applied to
    # in-bound NLRIs.
    # Default local-pref values is 100
    lp1 = path1.get_pattr(BGP_ATTR_TYPE_LOCAL_PREF)
    lp2 = path2.get_pattr(BGP_ATTR_TYPE_LOCAL_PREF)
    if not (lp1 and lp2):
        return None

    # Highest local-preference value is preferred.
    lp1 = lp1.value
    lp2 = lp2.value
    if lp1 > lp2:
        return path1
    elif lp2 > lp1:
        return path2
    else:
        return None


def _cmp_by_local_origin(path1, path2):
    """Select locally originating path as best path.

    Locally originating routes are network routes, redistributed routes,
    or aggregated routes. For now we are going to prefer routes received
    through a Flexinet-Peer as locally originating route compared to routes
    received from a BGP peer.
    Returns None if given paths have same source.
    """
    # If both paths are from same sources we cannot compare them here.
    if path1.source == path2.source:
        return None

    # Here we consider prefix from NC as locally originating static route.
    # Hence it is preferred.
    if path1.source is None:
        return path1

    if path2.source is None:
        return path2

    return None


def _cmp_by_aspath(path1, path2):
    """Calculated the best-paths by comparing as-path lengths.

    Shortest as-path length is preferred. If both path have same lengths,
    we return None.
    """
    as_path1 = path1.get_pattr(BGP_ATTR_TYPE_AS_PATH)
    as_path2 = path2.get_pattr(BGP_ATTR_TYPE_AS_PATH)
    assert as_path1 and as_path2
    l1 = as_path1.get_as_path_len()
    l2 = as_path2.get_as_path_len()
    assert l1 is not None and l2 is not None
    if l1 > l2:
        return path2
    elif l2 > l1:
        return path1
    else:
        return None


def _cmp_by_origin(path1, path2):
    """Select the best path based on origin attribute.

    IGP is preferred over EGP; EGP is preferred over Incomplete.
    If both paths have same origin, we return None.
    """
    def get_origin_pref(origin):
        if origin.value == BGP_ATTR_ORIGIN_IGP:
            return 3
        elif origin.value == BGP_ATTR_ORIGIN_EGP:
            return 2
        elif origin.value == BGP_ATTR_ORIGIN_INCOMPLETE:
            return 1
        else:
            LOG.error('Invalid origin value encountered %s.', origin)
            return 0

    origin1 = path1.get_pattr(BGP_ATTR_TYPE_ORIGIN)
    origin2 = path2.get_pattr(BGP_ATTR_TYPE_ORIGIN)
    assert origin1 is not None and origin2 is not None

    # If both paths have same origins
    if origin1.value == origin2.value:
        return None

    # Translate origin values to preference.
    origin1 = get_origin_pref(origin1)
    origin2 = get_origin_pref(origin2)
    # Return preferred path.
    if origin1 == origin2:
        return None
    elif origin1 > origin2:
        return path1
    return path2


def _cmp_by_med(path1, path2):
    """Select the path based with lowest MED value.

    If both paths have same MED, return None.
    By default, a route that arrives with no MED value is treated as if it
    had a MED of 0, the most preferred value.
    RFC says lower MED is preferred over higher MED value.
    """
    def get_path_med(path):
        med = path.get_pattr(BGP_ATTR_TYPE_MULTI_EXIT_DISC)
        if not med:
            return 0
        return med.value

    med1 = get_path_med(path1)
    med2 = get_path_med(path2)

    if med1 == med2:
        return None
    elif med1 < med2:
        return path1
    return path2


def _cmp_by_asn(local_asn, path1, path2):
    """Select the path based on source (iBGP/eBGP) peer.

    eBGP path is preferred over iBGP. If both paths are from same kind of
    peers, return None.
    """
    def get_path_source_asn(path):
        asn = None
        if path.source is None:
            asn = local_asn
        else:
            asn = path.source.remote_as
        return asn

    p1_asn = get_path_source_asn(path1)
    p2_asn = get_path_source_asn(path2)
    # If path1 is from ibgp peer and path2 is from ebgp peer.
    if (p1_asn == local_asn) and (p2_asn != local_asn):
        return path2

    # If path2 is from ibgp peer and path1 is from ebgp peer,
    if (p2_asn == local_asn) and (p1_asn != local_asn):
        return path1

    # If both paths are from ebgp or ibpg peers, we cannot decide.
    return None


def _cmp_by_igp_cost(path1, path2):
    """Select the route with the lowest IGP cost to the next hop.

    Return None if igp cost is same.
    """
    # TODO(PH): Currently BGPS has no concept of IGP and IGP cost.
    return None


def _cmp_by_router_id(local_asn, path1, path2):
    """Select the route received from the peer with the lowest BGP router ID.

    If both paths are eBGP paths, then we do not do any tie breaking, i.e we do
    not pick best-path based on this criteria.
    RFC: http://tools.ietf.org/html/rfc5004
    We pick best path between two iBGP paths as usual.
    """
    def get_asn(path_source):
        if path_source is None:
            return local_asn
        else:
            return path_source.remote_as

    def get_router_id(path_source, local_bgp_id):
        if path_source is None:
            return local_bgp_id
        else:
            return path_source.protocol.recv_open_msg.bgp_identifier

    path_source1 = path1.source
    path_source2 = path2.source

    # If both paths are from NC we have same router Id, hence cannot compare.
    if path_source1 is None and path_source2 is None:
        return None

    asn1 = get_asn(path_source1)
    asn2 = get_asn(path_source2)

    is_ebgp1 = asn1 != local_asn
    is_ebgp2 = asn2 != local_asn
    # If both paths are from eBGP peers, then according to RFC we need
    # not tie break using router id.
    if (is_ebgp1 and is_ebgp2):
        return None

    if ((is_ebgp1 is True and is_ebgp2 is False) or
            (is_ebgp1 is False and is_ebgp2 is True)):
        raise ValueError('This method does not support comparing ebgp with'
                         ' ibgp path')

    # At least one path is not coming from NC, so we get local bgp id.
    if path_source1 is not None:
        local_bgp_id = path_source1.protocol.sent_open_msg.bgp_identifier
    else:
        local_bgp_id = path_source2.protocol.sent_open_msg.bgp_identifier

    # Get router ids.
    router_id1 = get_router_id(path_source1, local_bgp_id)
    router_id2 = get_router_id(path_source2, local_bgp_id)

    # If both router ids are same/equal we cannot decide.
    # This case is possible since router ids are arbitrary.
    if router_id1 == router_id2:
        return None

    # Select the path with lowest router Id.
    from ryu.services.protocols.bgp.utils.bgp import from_inet_ptoi
    if (from_inet_ptoi(router_id1) < from_inet_ptoi(router_id2)):
        return path1
    else:
        return path2
