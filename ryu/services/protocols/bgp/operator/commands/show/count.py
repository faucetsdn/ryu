import logging

from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp

LOG = logging.getLogger('bgpspeaker.operator.commands.show.count')


class Count(Command):
    help_msg = 'show counters'
    param_help_msg = '<vpn-name> <route-family>{ipv4, ipv6}'
    command = 'count'
    cli_resp_line_template = 'BGP route count for VPN {0} is {1}\n'

    def __init__(self, *args, **kwargs):
        super(Count, self).__init__(*args, **kwargs)
        self.subcommands = {
            'all': self.All
        }

    def action(self, params):
        if len(params) < 1:
            return CommandsResponse(STATUS_ERROR, 'Not enough params')
        else:
            vrf_name = params[0]
            if len(params) == 2:
                vrf_rf = params[1]
            else:
                vrf_rf = 'ipv4'

            from ryu.services.protocols.bgp.operator.internal_api import \
                WrongParamError
            try:
                return CommandsResponse(
                    STATUS_OK,
                    self.api.count_single_vrf_routes(vrf_name, vrf_rf)
                )
            except WrongParamError as e:
                return WrongParamResp(e)

    class All(Command):
        help_msg = 'shows number of routes for all VRFs'
        command = 'all'
        cli_resp_line_template = 'BGP route count for VPN {0} is {1}\n'

        def action(self, params):
            if len(params) > 0:
                return WrongParamResp()
            return CommandsResponse(STATUS_OK, self.api.count_all_vrf_routes())
