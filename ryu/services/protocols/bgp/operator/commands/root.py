from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.commands.clear import ClearCmd
from ryu.services.protocols.bgp.operator.commands.set import SetCmd
from ryu.services.protocols.bgp.operator.commands.show import ShowCmd


class RootCmd(Command):
    subcommands = {
        'show': ShowCmd,
        'set': SetCmd,
        'clear': ClearCmd}
