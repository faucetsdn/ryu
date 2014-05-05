import platform
import datetime
import json
import logging
import time

_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

APGW_KEYS = [
    'log_type',
]


def convert_str_to_log_level(log_level):
    try:
        log_level = logging.__dict__[log_level.upper()]
    except KeyError:
        log_level = logging.INFO
    finally:
        return log_level


class LogTypeAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra=None, log_type='log'):
        self.log_type = log_type
        super(LogTypeAdapter, self).__init__(logger, extra)

    def process(self, msg, kwargs):
        kwargs['extra'] = dict(log_type=self.log_type)
        return msg, kwargs


class DictAndLogTypeAdapter(LogTypeAdapter):
    def process(self, msg, kwargs):
        msg, kwargs = super(DictAndLogTypeAdapter, self).process(msg, kwargs)
        for key in APGW_KEYS:
            try:
                value = msg.pop(key)
            except KeyError:
                continue
            else:
                kwargs['extra'][key] = value
        return msg, kwargs


class ApgwLogger(logging.getLoggerClass()):
    '''Insert component name and log type into a log record.

    NOTE: Set ApgwLogger as the logger as the first thing you do with logging.
    A good way (followed here) would be to do this in the __init__.py in your
    package.
    '''
    _COMPONENT_NAME = 'agent'
    _DEFAULT_LOG_TYPE = 'log'

    def __init__(self, *args, **kwargs):
        self.component_name = kwargs.pop('component_name',
                                         self._COMPONENT_NAME)
        super(ApgwLogger, self).__init__(*args, **kwargs)

    def makeRecord(self, *args, **kwargs):
        rv = super(ApgwLogger, self).makeRecord(*args, **kwargs)
        setattr(rv, 'component_name', self.component_name)
        if not hasattr(rv, 'log_type'):
            setattr(rv, 'log_type', self._DEFAULT_LOG_TYPE)
        return rv


class JsonFormatter(logging.Formatter):

    def __init__(self, component_name, *args, **kwargs):
        self.component_name = component_name
        super(JsonFormatter, self).__init__(*args, **kwargs)

    @staticmethod
    def _get_cur_time():
        cur_time = datetime.datetime.utcfromtimestamp(
            time.time()).strftime(_TIME_FORMAT)
        return cur_time

    def format(self, record):
        message = {
            'timestamp': self._get_cur_time(),
            'component_name': self.component_name,
            'log_level': record.levelname,
            'msg': record.msg,
        }

        for key in APGW_KEYS:
            try:
                value = getattr(record, key)
            except AttributeError:
                continue
            else:
                message[key] = value
        record.msg = '{name} {message}'.format(name=self.component_name,
                                               message=json.dumps(message))
        return super(JsonFormatter, self).format(record)


def configure_logging(log, component_name):
    log_level = logging.getLevelName(log.level)
    if log_level == 'NOTSET':
        log_level = logging.INFO
    log.setLevel(log_level)

    # we don't write to stdout unless the level is 'debug'.
#     if log_level is not logging.DEBUG:
#         for handler in log.handlers:
#             log.removeHandler(handler)

    # will be removed for the release version
    if platform.system() == 'Darwin':
        address = '/var/run/syslog'
    else:
        address = '/dev/log'

    syslog = logging.handlers.SysLogHandler(address=address)
    syslog.setFormatter(JsonFormatter(component_name=component_name))
    log.addHandler(syslog)
