import logging
import pprint

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

LOG = logging.getLogger('bgpspeaker.operator.commands.show.summary')


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
        ret = dict([
            (path['nlri']['formatted_nlri'], path)
            for path in ret
        ])

        return CommandsResponse(STATUS_OK, ret)

    def _retrieve_paths(self, addr_family, route_family, ip_addr):
        global_tables_view = self._retrieve_global_tables_view(
            addr_family,
            route_family
        )
        sent = global_tables_view.c_rel('destinations').c_rel('sent_routes')
        sent.apply_filter(
            lambda route: route.sent_peer.ip_address == ip_addr
        )
        paths = sent.c_rel('path')
        paths.apply_filter(
            lambda path: not path.is_withdraw
        )
        return paths

    def _retrieve_global_tables_view(self, addr_family, route_family):
        core_service = self.api.get_core_service()
        core_sv = CoreServiceDetailView(core_service)
        table_manager_view = core_sv.rel('table_manager')
        global_tables_view = table_manager_view.rel('global_tables')
        global_tables_view.apply_filter(
            lambda k, v: addr_family == 'all' or k == route_family
        )
        return global_tables_view

    @classmethod
    def cli_resp_formatter(cls, resp):
        if resp.status == STATUS_ERROR:
            return Command.cli_resp_formatter(resp)

        return '\n{0}'.format(pprint.pformat(resp.value))


class ReceivedRoutes(SentRoutes):
    help_msg = 'paths received and not withdrawn by given peer'
    command = 'received-routes'

    def _retrieve_paths(self, addr_family, route_family, ip_addr):
        global_tables_view = self._retrieve_global_tables_view(
            addr_family,
            route_family
        )
        paths = global_tables_view.c_rel(
            'destinations'
        ).c_rel('known_path_list')

        def path_filter(path):
            return path.source is not None and \
                path.source.ip_address == ip_addr and \
                not path.is_withdraw

        paths.apply_filter(
            path_filter
        )
        return paths


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
                                 for k, v in ret.iteritems()])

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
