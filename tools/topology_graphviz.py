#! /usr/bin/env python

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# usage example:
# curl http://localhost:8080/v1.0/topology/links|./topology_graphviz.py|neato -Tx11

import json
import sys

j = sys.stdin.read()
l = json.loads(j)

print 'digraph {'
print 'node [shape=box]'
for d in l:
    print '"%s" -> "%s";' % (d['src']['dpid'], d['dst']['dpid'])
print 'overlap=false'
print '}'
