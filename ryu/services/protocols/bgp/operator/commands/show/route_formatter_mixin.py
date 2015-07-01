import six


class RouteFormatterMixin(object):

    fmtstr = ' {0:<3s} {1:<32s} {2:<8s} {3:<20s} {4:<15s} '\
        '{5:<6s} {6:<6s} {7:<}\n'

    @classmethod
    def _format_family_header(cls):
        ret = ''
        ret += ('Status codes: * valid, > best\n')
        ret += ('Origin codes: i - IGP, e - EGP, ? - incomplete\n')
        ret += cls.fmtstr.format('', 'Network', 'Labels', 'Next Hop', 'Reason',
                                 'Metric', 'LocPrf', 'Path')
        return ret

    @classmethod
    def _format_family(cls, dest_list):
        if six.PY3:
            import io
            msg = io.StringIO()
        else:
            import StringIO
            msg = StringIO.StringIO()

        def _append_path_info(buff, path, is_best, show_prefix):
            aspath = path.get('aspath')
            origin = path.get('origin')
            if origin:
                aspath.append(origin)

            bpr = path.get('bpr')
            next_hop = path.get('nexthop')
            med = path.get('metric')
            labels = path.get('labels')
            localpref = path.get('localpref')
            # Construct path status string.
            path_status = '*'
            if is_best:
                path_status += '>'

            # Check if we want to show prefix.
            prefix = ''
            if show_prefix:
                prefix = path.get('prefix')

            # Append path info to String buffer.
            buff.write(cls.fmtstr.format(path_status, prefix, labels,
                                         next_hop, bpr, str(med),
                                         str(localpref),
                                         ' '.join(map(str, aspath))))

        for dist in dest_list:
            for idx, path in enumerate(dist.get('paths')):
                _append_path_info(msg, path, path['best'], (idx == 0))
        ret = msg.getvalue()
        msg.close()
        return ret
