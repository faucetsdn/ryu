# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
 Module for stats related classes and utilities.
"""
import datetime
import json
import logging
import time

from ryu.services.protocols.bgp.rtconf.base import ConfWithId


_STATS_LOGGER = logging.getLogger('stats')

# Various stats related constants.
DEFAULT_LOG_LEVEL = logging.INFO

RESOURCE_ID = 'resource_id'
RESOURCE_NAME = 'resource_name'
TIMESTAMP = 'timestamp'
LOG_LEVEL = 'log_level'

STATS_RESOURCE = 'stats_resource'
STATS_SOURCE = 'stats_source'

# VRF related stat constants
REMOTE_ROUTES = 'remote_routes'
LOCAL_ROUTES = 'local_routes'

# Peer related stat constant.
UPDATE_MSG_IN = 'update_message_in'
UPDATE_MSG_OUT = 'update_message_out'
TOTAL_MSG_IN = 'total_message_in'
TOTAL_MSG_OUT = 'total_message_out'
FMS_EST_TRANS = 'fsm_established_transitions'
UPTIME = 'uptime'


def log(stats_resource=None, stats_source=None, log_level=DEFAULT_LOG_LEVEL,
        **kwargs):
    """Utility to log given stats to *stats* logger.

    Stats to log are given by `stats_source` and in its absence we log
    `kwargs`. *stats* logger is configured independently from any logger.
    Only stats should be logged to this logger. Will add current timestamp
    to the logged stats if not given.

    Parameters:
        - `stats_resource`: any object that complies with `id` and `name`
        attrs.
        - `stats_source`: any callable that give a `dict` that will be
        logged to *stats* logger.
        - `log_level`: str representing level at which to log this stats
        message.
        - `**kwargs`: if `stats_source` is not given, we log this `dict`.
    """

    # Get stats from source if given.
    if stats_source is not None:
        kwargs = stats_source()

    if stats_resource is None:
        if RESOURCE_ID not in kwargs or RESOURCE_NAME not in kwargs:
            raise ValueError('Missing required stats labels.')
    else:
        if not (hasattr(stats_resource, ConfWithId.ID) and
                hasattr(stats_resource, ConfWithId.NAME)):
            raise ValueError('Given stats source is missing id or name'
                             ' attributes.')
        kwargs[RESOURCE_ID] = stats_resource.id
        kwargs[RESOURCE_NAME] = stats_resource.name

    if TIMESTAMP not in kwargs:
        kwargs[TIMESTAMP] = datetime.datetime.utcfromtimestamp(
            time.time()).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    _STATS_LOGGER.log(log_level,
                      json.dumps(kwargs))


def logd(**kwargs):
    log(log_level=logging.DEBUG, **kwargs)


def logi(**kwargs):
    log(log_level=logging.INFO, **kwargs)
