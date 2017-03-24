import logging
from time import strftime

from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp
from ryu.services.protocols.bgp.operator.views.bgp import CoreServiceDetailView
from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_IGP
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_EGP
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_INCOMPLETE

LOG = logging.getLogger('bgpspeaker.operator.commands.show.neighbor')


class NeighborSummary(Command):
    help_msg = 'show summarized neighbor information'
    command = 'summary'

    def action(self, params):
        requested_peers = []
        if len(params) > 0:
            requested_peers = [str(p) for p in params]

        core_service = self.api.get_core_service()
        core_service_view = CoreServiceDetailView(core_service)
        peers_view = core_service_view.rel('peer_manager').rel('peers_summary')

        def filter_requested(peer_id, peer_obj):
            return not requested_peers or peer_id in requested_peers

        peers_view.apply_filter(filter_requested)
        ret = peers_view.encode()
        return CommandsResponse(STATUS_OK, ret)


class SentRoutes(Command):
    help_msg = 'paths sent and not withdrawn to given peer'
    command = 'sent-routes'
    param_help_msg = '<ip_addr> <addr_family>{vpnv4, vpnv6, ipv4, ipv6, all}'
    fmtstr = ' {0:<2s} {1:<19s} {2:<32s} {3:<8s} {4:<20s} '\
        '{5:<6s} {6:<6s} {7:<}\n'

    def action(self, params):
        if len(params) != 2:
            return WrongParamResp()
        ip_addr, addr_family = params

        if addr_family == 'ipv4':
            rf = RF_IPv4_UC
        elif addr_family == 'ipv6':
            rf = RF_IPv6_UC
        elif addr_family == 'vpnv4':
            rf = RF_IPv4_VPN
        elif addr_family == 'vpnv6':
            rf = RF_IPv6_VPN
        elif addr_family == 'all':
            rf = None
        else:
            return WrongParamResp('wrong addr_family name')

        ret = self._retrieve_paths(addr_family, rf, ip_addr).encode()
        return CommandsResponse(STATUS_OK, ret)

    def _retrieve_paths(self, addr_family, route_family, ip_addr):
        peer_view = self._retrieve_peer_view(ip_addr)
        adj_rib_out = peer_view.c_rel('adj_rib_out')
        adj_rib_out.apply_filter(lambda k, v: addr_family == 'all' or
                                 v.path.route_family == route_family)
        return adj_rib_out

    def _retrieve_peer_view(self, ip_addr):
        core_service = self.api.get_core_service()
        core_sv = CoreServiceDetailView(core_service)
        peers_view = core_sv.rel('peer_manager').rel('peers')
        peers_view.apply_filter(lambda k, v: v.ip_address == ip_addr)
        return peers_view

    @classmethod
    def cli_resp_formatter(cls, resp):
        if resp.status == STATUS_ERROR:
            return Command.cli_resp_formatter(resp)
        return cls._format_header() + cls._format_value(resp.value)

    @classmethod
    def _format_header(cls):
        ret = ''
        ret += ('Status codes: x filtered\n')
        ret += ('Origin codes: i - IGP, e - EGP, ? - incomplete\n')
        ret += cls.fmtstr.format('', 'Timestamp', 'Network', 'Labels',
                                 'Next Hop', 'Metric', 'LocPrf', 'Path')
        return ret

    @classmethod
    def _format_value(cls, value):
        ret = ''
        for v in value:
            path = v.get('path')
            aspath = path.get('as_path')
            origin = path.get('origin')

            if origin == BGP_ATTR_ORIGIN_IGP:
                origin = 'i'
            elif origin == BGP_ATTR_ORIGIN_EGP:
                origin = 'e'
            elif origin == BGP_ATTR_ORIGIN_INCOMPLETE:
                origin = '?'

            if origin:
                aspath = aspath + [origin]

            next_hop = path.get('nexthop')
            med = path.get('metric')
            labels = path.get('labels')
            localpref = path.get('local_pref')
            prefix = path.get('nlri').get('prefix')

            path_status = ''
            if v.get('filtered'):
                path_status = 'x'
            time = 'N/A'
            if v.get('timestamp'):
                time = strftime("%Y/%m/%d %H:%M:%S", v.get('timestamp'))
            ret += cls.fmtstr.format(path_status, time, prefix, labels,
                                     str(next_hop), str(med), str(localpref),
                                     ' '.join(map(str, aspath)))
        return ret


class ReceivedRoutes(SentRoutes):
    help_msg = 'paths received and not withdrawn by given peer'
    command = 'received-routes'

    def _retrieve_paths(self, addr_family, route_family, ip_addr):
        peer_view = self._retrieve_peer_view(ip_addr)
        adj_rib_in = peer_view.c_rel('adj_rib_in')
        adj_rib_in.apply_filter(lambda k, v: addr_family == 'all' or
                                v.path.route_family == route_family)
        return adj_rib_in


class Neighbor(Command):
    help_msg = 'show neighbor information'
    command = 'neighbor'
    subcommands = {
        'summary': NeighborSummary,
        'sent-routes': SentRoutes,
        'received-routes': ReceivedRoutes
    }

    fmtstr = ' {0:<12s} {1:<12s} {2:<}\n'

    def action(self, params):
        core_service = self.api.get_core_service()
        core_service_view = CoreServiceDetailView(core_service)
        peers_view = core_service_view.rel('peer_manager').rel('peers')

        ret = peers_view.encode()
        return CommandsResponse(STATUS_OK,
                                [{'ip_addr': k,
                                  'as_num': str(v['remote_as']),
                                  'bgp_state': v['stats']['bgp_state']}
                                 for k, v in ret.items()])

    @classmethod
    def cli_resp_formatter(cls, resp):
        if resp.status == STATUS_ERROR:
            return Command.cli_resp_formatter(resp)
        return cls._format_header() + cls._format_value(resp.value)

    @classmethod
    def _format_header(cls):
        return cls.fmtstr.format('IP Address', 'AS Number', 'BGP State')

    @classmethod
    def _format_value(cls, value):
        ret = ''
        for v in value:
            ret += cls.fmtstr.format(v['ip_addr'], v['as_num'], v['bgp_state'])
        return ret
