import gc
import sys

from ryu.services.protocols.bgp.operator.command import Command
from ryu.services.protocols.bgp.operator.command import CommandsResponse
from ryu.services.protocols.bgp.operator.command import STATUS_ERROR
from ryu.services.protocols.bgp.operator.command import STATUS_OK


class Memory(Command):
    help_msg = 'show memory information'
    command = 'memory'

    def __init__(self, *args, **kwargs):
        super(Memory, self).__init__(*args, **kwargs)
        self.subcommands = {
            'summary': self.Summary}

    class Summary(Command):
        help_msg = 'shows total memory used and how it is getting used'
        command = 'summary'

        def action(self, params):
            count = {}
            size = {}
            total_size = 0
            unreachable = gc.collect()
            for obj in gc.get_objects():
                inst_name = type(obj).__name__
                c = count.get(inst_name, None)
                if not c:
                    count[inst_name] = 0
                s = size.get(inst_name, None)
                if not s:
                    size[inst_name] = 0

                count[inst_name] += 1
                s = sys.getsizeof(obj)
                size[inst_name] += s
                total_size += s

            # Total size in MB

            total_size = total_size // 1000000
            ret = {
                'unreachable': unreachable,
                'total': total_size,
                'summary': []}

            for class_name, s in size.items():
                # Calculate size in MB
                size_mb = s // 1000000
                # We are only interested in class which take-up more than a MB
                if size_mb > 0:
                    ret['summary'].append(
                        {
                            'class': class_name,
                            'instances': count.get(class_name, None),
                            'size': size_mb
                        }
                    )

            return CommandsResponse(STATUS_OK, ret)

        @classmethod
        def cli_resp_formatter(cls, resp):
            if resp.status == STATUS_ERROR:
                return Command.cli_resp_formatter(resp)
            val = resp.value
            ret = 'Unreachable objects: {0}\n'.format(
                val.get('unreachable', None)
            )
            ret += 'Total memory used (MB): {0}\n'.format(
                val.get('total', None)
            )
            ret += 'Classes with instances that take-up more than one MB:\n'
            ret += '{0:<20s} {1:>16s} {2:>16s}\n'.format(
                'Class',
                '#Instance',
                'Size(MB)'
            )

            for s in val.get('summary', []):
                ret += '{0:<20s} {1:>16d} {2:>16d}\n'.format(
                    s.get('class', None), s.get('instances', None),
                    s.get('size', None)
                )

            return ret
