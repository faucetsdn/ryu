from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp

from ryu.services.protocols.bgp.operator.views.bgp import CoreServiceDetailView


class Importmap(Command):
    help_msg = 'show importmaps'
    param_help_msg = 'all | <name>'
    command = 'importmap'

    def __init__(self, *args, **kwargs):
        super(Importmap, self).__init__(*args, **kwargs)

    def action(self, params):
        if len(params) != 1:
            return WrongParamResp()

        core_service = self.api.get_core_service()
        core_service_view = CoreServiceDetailView(core_service)
        importmap_manager = core_service_view.rel('importmap_manager')
        importmaps_view = importmap_manager.rel('importmaps')

        importmap_name = params[0]
        if importmap_name == 'all':
            encoded = importmaps_view.encode()
        else:
            encoded = importmaps_view.encode().get(importmap_name)
            if encoded is None:
                return CommandsResponse(
                    STATUS_ERROR,
                    'Wrong importmap name.'
                )

        return CommandsResponse(
            STATUS_OK,
            encoded
        )
