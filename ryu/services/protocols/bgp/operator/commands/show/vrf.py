from __future__ import absolute_import

import logging
import pprint

from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp
from ryu.services.protocols.bgp.operator.views.conf import ConfDetailView
from ryu.services.protocols.bgp.operator.views.conf import ConfDictView
from .route_formatter_mixin import RouteFormatterMixin

LOG = logging.getLogger('bgpspeaker.operator.commands.show.vrf')

SUPPORTED_VRF_RF = ('ipv4', 'ipv6', 'evpn')


class Routes(Command, RouteFormatterMixin):
    help_msg = 'show routes present for vrf'
    param_help_msg = '<vpn-name> <route-family>%s' % str(SUPPORTED_VRF_RF)
    command = 'routes'

    def __init__(self, *args, **kwargs):
        super(Routes, self).__init__(*args, **kwargs)
        self.subcommands = {
            'all': self.All,
        }

    def action(self, params):
        if len(params) != 2:
            return WrongParamResp()
        vrf_name = params[0]
        vrf_rf = params[1]
        if vrf_rf not in SUPPORTED_VRF_RF:
            return WrongParamResp('route-family not one of %s' %
                                  str(SUPPORTED_VRF_RF))

        from ryu.services.protocols.bgp.operator.internal_api import \
            WrongParamError

        try:
            return CommandsResponse(
                STATUS_OK,
                self.api.get_single_vrf_routes(vrf_name, vrf_rf)
            )
        except WrongParamError as e:
            return CommandsResponse(
                STATUS_ERROR,
                'wrong parameters: %s' % str(e)
            )

    @classmethod
    def cli_resp_formatter(cls, resp):
        if resp.status == STATUS_ERROR:
            return super(Routes, cls).cli_resp_formatter(resp)
        return cls._format_family_header() + cls._format_family(resp.value)

    class All(Command, RouteFormatterMixin):
        help_msg = 'show routes for all VRFs'
        command = 'all'

        def action(self, params):
            if len(params) != 0:
                return WrongParamResp()
            return CommandsResponse(
                STATUS_OK,
                self.api.get_all_vrf_routes()
            )

        @classmethod
        def cli_resp_formatter(cls, resp):
            if resp.status == STATUS_ERROR:
                return Command.cli_resp_formatter(resp)
            ret = cls._format_family_header()
            for family, data in resp.value.items():
                ret += 'VPN: {0}\n'.format(family)
                ret += cls._format_family(data)
            return ret


class CountRoutesMixin(object):
    api = None  # not assigned yet

    def _count_routes(self, vrf_name, vrf_rf):
        return len(self.api.get_single_vrf_routes(vrf_name, vrf_rf))


class Summary(Command, CountRoutesMixin):
    help_msg = 'show configuration and summary of vrf'
    param_help_msg = '<rd> <route_family>| all'
    command = 'summary'

    def __init__(self, *args, **kwargs):
        super(Summary, self).__init__(*args, **kwargs)
        self.subcommands = {
            'all': self.All
        }

    def action(self, params):
        if len(params) == 0:
            return WrongParamResp('Not enough params')

        vrf_confs = self.api.get_vrfs_conf()
        if len(params) < 2:
            vrf_rf = 'ipv4'
        else:
            vrf_rf = params[1]

        vrf_key = params[0], vrf_rf

        if vrf_key in vrf_confs:
            view = ConfDetailView(vrf_confs[vrf_key])
            encoded = view.encode()
            encoded['routes_count'] = self._count_routes(params[0], vrf_rf)
        else:
            return WrongParamResp('No vrf matched by %s' % str(vrf_key))

        return CommandsResponse(
            STATUS_OK,
            encoded
        )

    @classmethod
    def cli_resp_formatter(cls, resp):
        if resp.status == STATUS_ERROR:
            return Command.cli_resp_formatter(resp)
        return pprint.pformat(resp.value)

    class All(Command, CountRoutesMixin):
        command = 'all'
        help_msg = 'shows all vrfs configurations and summary'

        def action(self, params):
            vrf_confs = self.api.get_vrfs_conf()
            view = ConfDictView(vrf_confs)
            encoded = view.encode()
            for vrf_key, conf in encoded.items():
                vrf_name, vrf_rf = vrf_key
                conf['routes_count'] = self._count_routes(
                    vrf_name,
                    vrf_rf
                )

            encoded = dict([(str(k), v)
                            for k, v in encoded.items()])
            return CommandsResponse(
                STATUS_OK,
                encoded
            )

        def _count_routes(self, vrf_name, vrf_rf):
            return len(self.api.get_single_vrf_routes(vrf_name, vrf_rf))


class Vrf(Routes):
    """Main node for vrf related commands. Acts also as Routes node (that's why
    it inherits from it) for legacy reasons.
    """
    help_msg = 'vrf related commands subtree'
    command = 'vrf'

    def __init__(self, *args, **kwargs):
        super(Vrf, self).__init__(*args, **kwargs)
        self.subcommands.update({
            'routes': Routes,
            'summary': Summary
        })
