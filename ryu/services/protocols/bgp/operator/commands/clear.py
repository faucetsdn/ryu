from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp


class BGPCmd(Command):
    help_msg = ('reset bgp connections, no afi/safi is '
                'treated as - all supported address-families')
    param_help_msg = '<peer_ip> [<afi> <safi>]'
    command = 'bgp'

    def __init__(self, *args, **kwargs):
        super(BGPCmd, self).__init__(*args, **kwargs)

        self.subcommands = {'all': self.All}

    def action(self, params):
        if len(params) == 0:
            return WrongParamResp()
        peer = afi = safi = None
        try:
            peer = params[0]
            afi = params[1]
            safi = params[2]
        except IndexError:
            pass

        self.api.route_refresh(peer, afi, safi)
        return CommandsResponse(STATUS_OK, '')

    class All(Command):
        help_msg = 'reset all connections'
        param_help_msg = '[<afi=> <safi=>]'
        command = 'all'

        def action(self, params):
            peer = afi = safi = None
            try:
                afi = params[0]
                safi = params[1]
            except IndexError:
                pass

            self.api.route_refresh(peer, afi, safi)
            return CommandsResponse(STATUS_OK, '')


class ClearCmd(Command):
    help_msg = 'allows to reset BGP connections'
    command = 'clear'

    subcommands = {'bgp': BGPCmd}
