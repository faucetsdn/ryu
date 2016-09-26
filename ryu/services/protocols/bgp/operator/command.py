from collections import namedtuple
import json
import logging
import pprint
import re
import six

(STATUS_OK, STATUS_ERROR) = range(2)

CommandsResponse = namedtuple('CommandsResponse', ['status', 'value'])

LOG = logging.getLogger('bgpspeaker.operator.command')


def default_help_formatter(quick_helps):
    """Apply default formatting for help messages

        :param quick_helps: list of tuples containing help info
     """
    ret = ''
    for line in quick_helps:
        cmd_path, param_hlp, cmd_hlp = line
        ret += ' '.join(cmd_path) + ' '
        if param_hlp:
            ret += param_hlp + ' '
        ret += '- ' + cmd_hlp + '\n'
    return ret


class Command(object):
    """Command class is used as a node in tree of commands.

    Each command can do some action or have some sub-commands, just like in IOS
    Command with it's sub-commands form tree.
    Each command can have one or more parameters. Parameters have to be
    distinguishable from sub-commands.
        One can inject dependency into command Cmd(api=my_object).
    This dependency will be injected to every sub-command. And can be used
    to interact with model/data etc.
        Example of path in command tree `show count all`.
    """

    help_msg = ''
    param_help_msg = ''
    command = ''
    cli_resp_line_template = '{0}: {1}\n'

    def __init__(self, api=None, parent=None,
                 help_formatter=default_help_formatter,
                 resp_formatter_name='cli'):
        """:param api: object which is saved as self.api
                 and re-injected to every sub-command. You can use it to
                 manipulate your model from inside Commands'
           :param parent: parent command instance.
           :param help_formatter: function used to format
                output of '?'command. Is re-injected to every
                sub-command as well.
           :param resp_formatter_name: used to select function to format
                output of _action. cli_resp_formatter and json_resp_formatter
                are defined by default, but you can define your own formatters.
                If you use custom formatter(not cli nor json) remember to
                implement it for every sub-command.
        """

        self.resp_formatter_name = resp_formatter_name

        if hasattr(self, resp_formatter_name + '_resp_formatter'):
            self.resp_formatter = \
                getattr(self, resp_formatter_name + '_resp_formatter')
        else:
            self.resp_formatter = self.cli_resp_formatter

        self.api = api
        self.parent_cmd = parent
        self.help_formatter = help_formatter
        if not hasattr(self, 'subcommands'):
            self.subcommands = {}

    def __call__(self, params):
        """You run command by calling it.

        :param params: As params you give list of subcommand names
            and params to final subcommand. Kind of like in
            cisco ios cli, ie. show int eth1 / 1, where show is command,
            int subcommand and eth1 / 1 is param for subcommand.
        :return: returns tuple of CommandsResponse and class of
            sub - command on which _action was called. (last sub - command)
            CommandsResponse.status is action status,
            and CommandsResponse.value is formatted response.
        """
        if len(params) == 0:
            return self._action_wrapper([])

        first_param = params[0]

        if first_param == '?':
            return self.question_mark()

        if first_param in self.subcommands:
            return self._instantiate_subcommand(first_param)(params[1:])

        return self._action_wrapper(params)

    @classmethod
    def cli_resp_formatter(cls, resp):
        """Override this method to provide custom formatting of cli response.
        """
        if not resp.value:
            return ''

        if resp.status == STATUS_OK:

            if type(resp.value) in (str, bool, int, float, six.text_type):
                return str(resp.value)

            ret = ''
            val = resp.value
            if not isinstance(val, list):
                val = [val]
            for line in val:
                for k, v in line.items():
                    if isinstance(v, dict):
                        ret += cls.cli_resp_line_template.format(
                            k, '\n' + pprint.pformat(v)
                        )
                    else:
                        ret += cls.cli_resp_line_template.format(k, v)
            return ret
        else:
            return "Error: {0}".format(resp.value)

    @classmethod
    def json_resp_formatter(cls, resp):
        """Override this method to provide custom formatting of json response.
        """
        return json.dumps(resp.value)

    @classmethod
    def dict_resp_formatter(cls, resp):
        return resp.value

    def _action_wrapper(self, params):
        filter_params = []
        if '|' in params:
            ind = params.index('|')
            new_params = params[:ind]
            filter_params = params[ind:]
            params = new_params

        action_resp = self.action(params)
        if len(filter_params) > 1:
            # we don't pass '|' around so filter_params[1:]
            action_resp = self.filter_resp(action_resp, filter_params[1:])
        action_resp = CommandsResponse(
            action_resp.status,
            self.resp_formatter(action_resp)
        )
        return action_resp, self.__class__

    def action(self, params):
        """Override this method to define what command should do.

        :param params: list of text parameters applied to this command.
        :return: returns CommandsResponse instance.
                 CommandsResponse.status can be STATUS_OK or STATUS_ERROR
                 CommandsResponse.value should be dict or str
        """
        return CommandsResponse(STATUS_ERROR, 'Not implemented')

    def filter_resp(self, action_resp, filter_params):
        """Filter response of action. Used to make printed results more
        specific

        :param action_resp: named tuple (CommandsResponse)
            containing response from action.
        :param filter_params: params used after '|' specific for given filter
        :return: filtered response.
        """
        if action_resp.status == STATUS_OK:
            try:
                return CommandsResponse(
                    STATUS_OK,
                    TextFilter.filter(action_resp.value, filter_params)
                )
            except FilterError as e:
                return CommandsResponse(STATUS_ERROR, str(e))
        else:
            return action_resp

    def question_mark(self):
        """Shows help for this command and it's sub-commands.
        """
        ret = []
        if self.param_help_msg or len(self.subcommands) == 0:
            ret.append(self._quick_help())

        if len(self.subcommands) > 0:
            for k, _ in sorted(self.subcommands.items()):
                command_path, param_help, cmd_help = \
                    self._instantiate_subcommand(k)._quick_help(nested=True)
                if command_path or param_help or cmd_help:
                    ret.append((command_path, param_help, cmd_help))

        return (
            CommandsResponse(STATUS_OK, self.help_formatter(ret)),
            self.__class__
        )

    def _quick_help(self, nested=False):
        """:param nested: True if help is requested directly for this command
                    and False when help is requested for a list of possible
                    completions.
        """
        if nested:
            return self.command_path(), None, self.help_msg
        else:
            return self.command_path(), self.param_help_msg, self.help_msg

    def command_path(self):
        if self.parent_cmd:
            return self.parent_cmd.command_path() + [self.command]
        else:
            return [self.command]

    def _instantiate_subcommand(self, key):
        return self.subcommands[key](
            api=self.api,
            parent=self,
            help_formatter=self.help_formatter,
            resp_formatter_name=self.resp_formatter_name
        )


class TextFilter(object):

    @classmethod
    def filter(cls, action_resp_value, filter_params):
        try:
            action, expected_value = filter_params
        except ValueError:
            raise FilterError('Wrong number of filter parameters')
        if action == 'regexp':

            if isinstance(action_resp_value, list):
                resp = list(action_resp_value)
                iterator = enumerate(action_resp_value)
            else:
                resp = dict(action_resp_value)
                iterator = iter(action_resp_value.items())

            remove = []

            for key, value in iterator:
                if not re.search(expected_value, str(value)):
                    remove.append(key)

            if isinstance(resp, list):
                resp = [resp[key] for key, value in enumerate(resp)
                        if key not in remove]
            else:
                resp = dict([(key, value)
                             for key, value in resp.items()
                             if key not in remove])

            return resp
        else:
            raise FilterError('Unknown filter')


class FilterError(Exception):
    pass
