import logging

from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_OK
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.commands.responses import \
    WrongParamResp


class LoggingCmd(Command):
    command = 'logging'
    help_msg = 'turn on/off logging at current level'

    def __init__(self, *args, **kwargs):
        super(LoggingCmd, self).__init__(*args, **kwargs)
        self.subcommands = {
            'on': self.On,
            'off': self.Off,
            'level': self.Level
        }

    def action(self, params):
        return CommandsResponse(STATUS_ERROR, 'Command incomplete')

    class On(Command):
        command = 'on'
        help_msg = 'turn-on the logging at the current level'

        def action(self, params):
            logging.getLogger('bgpspeaker').addHandler(self.api.log_handler)
            return CommandsResponse(STATUS_OK, True)

    class Off(Command):
        command = 'off'
        help_msg = 'turn-off the logging'

        def action(self, params):
            logging.getLogger('bgpspeaker').removeHandler(self.api.log_handler)
            return CommandsResponse(STATUS_OK, True)

    class Level(Command):
        command = 'level'
        help_msg = 'set logging level'
        param_help_msg = '[debug/info/error]'

        def action(self, params):
            lvls = {
                'debug': logging.DEBUG,
                'error': logging.ERROR,
                'info': logging.INFO
            }
            if len(params) == 1 and params[0] in lvls:
                self.api.log_handler.setLevel(
                    lvls.get(params[0], logging.ERROR)
                )
                return CommandsResponse(STATUS_OK, True)
            else:
                return WrongParamResp()


class SetCmd(Command):
    help_msg = 'set runtime settings'
    command = 'set'

    subcommands = {'logging': LoggingCmd}

    def action(self, params):
        return CommandsResponse(STATUS_ERROR, 'Command incomplete')
