# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import logging
import json
import httplib

LOG = logging.getLogger('ryu.gui')

_FLOW_PATH_BASE = '/stats/flow/'


def get_flows(address, dpid):
    assert type(dpid) == int

    flows = []
    try:
        path = '%s%d' % (_FLOW_PATH_BASE, dpid)
        flows = json.loads(_do_request(address, path).read())[str(dpid)]
    except IOError as e:
        LOG.error('REST API(%s) is not available.', address)
        raise
    except httplib.HTTPException as e:
        if e[0].status == httplib.NOT_FOUND:
            pass  # switch already deleted
        else:
            LOG.error('REST API(%s, path=%s) request error.', address, path)
            raise
    return flows


def _do_request(address, path):
    conn = httplib.HTTPConnection(address)
    conn.request('GET', path)
    res = conn.getresponse()
    if res.status in (httplib.OK,
                      httplib.CREATED,
                      httplib.ACCEPTED,
                      httplib.NO_CONTENT):
        return res

    raise httplib.HTTPException(
        res, 'code %d reason %s' % (res.status, res.reason),
        res.getheaders(), res.read())
