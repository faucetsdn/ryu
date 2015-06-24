import json
import logging
import six
import time

from datetime import datetime


class ApgwFormatter(logging.Formatter):
    LOG_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
    COMPONENT_NAME = 'BGPSpeaker'

    def format(self, record):
        msg = {
            'component_name': self.COMPONENT_NAME,
            'timestamp': datetime.utcfromtimestamp(
                time.time()
            ).strftime(self.LOG_TIME_FORMAT),
            'msg': six.text_type(record.msg),
            'level': record.levelname

        }

        if hasattr(record, 'log_type'):
            assert record.log_type in ('log', 'stats', 'state')
            msg['log_type'] = record.log_type
        else:
            msg['log_type'] = 'log'
        if hasattr(record, 'resource_id'):
            msg['resource_id'] = record.resource_id
        if hasattr(record, 'resource_name'):
            msg['resource_name'] = record.resource_name

        record.msg = json.dumps(msg)

        return super(ApgwFormatter, self).format(record)
