import StringIO


class RouteFormatterMixin(object):

    @classmethod
    def _format_family_header(cls):
        ret = ''
        ret += ('Status codes: * valid, > best\n')
        ret += ' {0:<3s} {1:<32s} {2:<20s} {3:<10s} {4:<20s} {5:<}\n'.format(
            '', 'Network', 'Next Hop', 'Reason', 'Metric', 'Path')
        return ret

    @classmethod
    def _format_family(cls, dest_list):
        msg = StringIO.StringIO()

        def _append_path_info(buff, path, is_best, show_prefix):
            aspath = path.get('aspath')
            origin = path.get('origin')
            if origin:
                aspath.append(origin)

            bpr = path.get('bpr')
            next_hop = path.get('nexthop')
            med = path.get('metric')
            # Construct path status string.
            path_status = '*'
            if is_best:
                path_status += '>'

            # Check if we want to show prefix.
            prefix = ''
            if show_prefix:
                prefix = path.get('prefix')

            # Append path info to String buffer.
            buff.write(
                ' {0:<3s} {1:<32s} {2:<20s} {3:<20s} {4:<10s} {5:<}\n'.
                format(path_status, prefix, next_hop, bpr, str(med),
                       ' '.join(map(str, aspath))))

        for dist in dest_list:
            for idx, path in enumerate(dist.get('paths')):
                _append_path_info(msg, path, path['best'], (idx == 0))
        ret = msg.getvalue()
        msg.close()
        return ret
