from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.commands.show import count
from ryu.services.protocols.bgp.operator.commands.show import importmap
from ryu.services.protocols.bgp.operator.commands.show import memory
from ryu.services.protocols.bgp.operator.commands.show import neighbor
from ryu.services.protocols.bgp.operator.commands.show import rib
from ryu.services.protocols.bgp.operator.commands.show import vrf


class ShowCmd(Command):
    help_msg = 'shows runtime state information'
    command = 'show'

    def __init__(self, *args, **kwargs):
        super(ShowCmd, self).__init__(*args, **kwargs)
        self.subcommands = {
            'count': self.Count,
            'logging': self.Logging,
            'rib': self.Rib,
            'vrf': self.Vrf,
            'memory': self.Memory,
            'neighbor': self.Neighbor,
            'importmap': self.Importmap
        }

    def action(self, params):
        return CommandsResponse(STATUS_ERROR, 'Command incomplete')

    class Count(count.Count):
        pass

    class Rib(rib.Rib):
        pass

    class Vrf(vrf.Vrf):
        pass

    class Importmap(importmap.Importmap):
        pass

    class Memory(memory.Memory):
        pass

    class Neighbor(neighbor.Neighbor):
        pass

    class Logging(Command):
        command = 'logging'
        help_msg = 'shows if logging is on/off and current logging level.'

        def action(self, params):
            if self.api.check_logging():
                ret = {'logging': self.api.check_logging(),
                       'level': self.api.check_logging_level()}
            else:
                ret = {'logging': self.api.check_logging(),
                       'level': None}
            return CommandsResponse(STATUS_OK, ret)
