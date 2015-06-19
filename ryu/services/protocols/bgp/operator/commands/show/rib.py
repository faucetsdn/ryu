from route_formatter_mixin import RouteFormatterMixin

from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.command import STATUS_OK

from ryu.services.protocols.bgp.base import ActivityException
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp


class RibBase(Command, RouteFormatterMixin):
    supported_families = ['ipv4', 'ipv6', 'vpnv4', 'rtfilter', 'vpnv6']


class Rib(RibBase):
    help_msg = 'show all routes for address family'
    param_help_msg = '<address-family>'
    command = 'rib'

    def __init__(self, *args, **kwargs):
        super(Rib, self).__init__(*args, **kwargs)
        self.subcommands = {
            'all': self.All}

    def action(self, params):
        if len(params) != 1 or params[0] not in self.supported_families:
            return WrongParamResp()
        from ryu.services.protocols.bgp.operator.internal_api \
            import WrongParamError
        try:
            return CommandsResponse(
                STATUS_OK,
                self.api.get_single_rib_routes(params[0])
            )
        except WrongParamError as e:
            return WrongParamResp(e)

    @classmethod
    def cli_resp_formatter(cls, resp):
        if resp.status == STATUS_ERROR:
            return RibBase.cli_resp_formatter(resp)
        return cls._format_family_header() + cls._format_family(resp.value)

    class All(RibBase):
        help_msg = 'show routes for all RIBs'
        command = 'all'

        def action(self, params):
            if len(params) != 0:
                return WrongParamResp()
            ret = {}
            try:
                for family in self.supported_families:
                    ret[family] = self.api.get_single_rib_routes(family)
                return CommandsResponse(STATUS_OK, ret)
            except ActivityException as e:
                return CommandsResponse(STATUS_ERROR, e)

        @classmethod
        def cli_resp_formatter(cls, resp):
            if resp.status == STATUS_ERROR:
                return RibBase.cli_resp_formatter(resp)
            ret = cls._format_family_header()
            for family, data in resp.value.items():
                ret += 'Family: {0}\n'.format(family)
                ret += cls._format_family(data)
            return ret
