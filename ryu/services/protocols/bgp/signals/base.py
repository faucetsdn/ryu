import logging
LOG = logging.getLogger('bgpspeaker.signals.base')


class SignalBus(object):
    def __init__(self):
        self._listeners = {}

    def emit_signal(self, identifier, data):
        identifier = _to_tuple(identifier)
        LOG.debug('SIGNAL: %s emited with data: %s ', identifier, data)
        for func, filter_func in self._listeners.get(identifier, []):
            if not filter_func or filter_func(data):
                func(identifier, data)

    def register_listener(self, identifier, func, filter_func=None):
        identifier = _to_tuple(identifier)
        substrings = (identifier[:i] for i in range(1, len(identifier) + 1))
        for partial_id in substrings:
            self._listeners.setdefault(
                partial_id,
                []
            ).append((func, filter_func))

    def unregister_all(self):
        self._listeners = {}


def _to_tuple(tuple_or_not):
    if not isinstance(tuple_or_not, tuple):
        return (tuple_or_not, )
    else:
        return tuple_or_not
