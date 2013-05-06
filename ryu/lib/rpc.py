import msgpack


class RpcMessage(object):
    REQUEST = 0
    RESPONSE = 1
    NOTIFY = 2


class RpcSession(object):
    def __init__(self):
        super(RpcSession, self).__init__()
        self._packer = msgpack.Packer()
        self._unpacker = msgpack.Unpacker()
        self._next_msgid = 0

    def _create_msgid(self):
        this_id = self._next_msgid
        self._next_msgid += 1
        return this_id

    def create_request(self, method, params):
        msgid = self._create_msgid()
        return self._packer.pack([RpcMessage.REQUEST, msgid, method, params])

    def create_response(self, msgid, error, result):
        return self._packer.pack([RpcMessage.RESPONSE, msgid, error, result])

    def create_notification(self, method, params):
        return self._packer.pack([RpcMessage.NOTIFY, method, params])

    def get_messages(self, data):
        self._unpacker.feed(data)
        messages = []
        for msg in self._unpacker:
            messages.append(msg)
        return messages
