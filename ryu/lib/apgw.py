import json
import datetime
import time
import logging

SYSLOG_FORMAT = '%(name)s %(message)s'


class StructuredMessage(object):
    COMPONENT_NAME = None

    def __init__(self, msg, log_type='log', resource_id=None,
                 resource_name=None):
        assert self.__class__.COMPONENT_NAME is not None
        assert isinstance(msg, dict)
        assert log_type in ('log', 'stats', 'states')
        self.message = {}
        cur_time = datetime.datetime.utcfromtimestamp(
            time.time()).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        self.message['log_type'] = log_type
        self.message['timestamp'] = cur_time
        self.message['component_name'] = self.__class__.COMPONENT_NAME
        self.message['msg'] = msg
        if resource_id:
            self.message['resource_id'] = resource_id
        if resource_name:
            self.message['resource_name'] = resource_name

    def __str__(self):
        return json.dumps(self.message)


def update_syslog_format():
    log = logging.getLogger()
    for h in log.handlers:
        if isinstance(h, logging.handlers.SysLogHandler):
            h.setFormatter(logging.Formatter(SYSLOG_FORMAT))
