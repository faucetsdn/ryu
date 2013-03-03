# Copyright 2009 Shikhar Bhushan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

'Boilerplate ugliness'

from ncclient.xml_ import *

from errors import OperationError, MissingCapabilityError

def one_of(*args):
    "Verifies that only one of the arguments is not None"
    for i, arg in enumerate(args):
        if arg is not None:
            for argh in args[i+1:]:
                if argh is not None:
                    raise OperationError("Too many parameters")
            else:
                return
    raise OperationError("Insufficient parameters")

def datastore_or_url(wha, loc, capcheck=None):
    node = new_ele(wha)
    if "://" in loc: # e.g. http://, file://, ftp://
        if capcheck is not None:
            capcheck(":url") # url schema check at some point!
            sub_ele(node, "url").text = loc
    else:
        #if loc == 'candidate':
        #    capcheck(':candidate')
        #elif loc == 'startup':
        #    capcheck(':startup')
        #elif loc == 'running' and wha == 'target':
        #    capcheck(':writable-running')
        sub_ele(node, loc)
    return node

def build_filter(spec, capcheck=None):
    type = None
    if isinstance(spec, tuple):
        type, criteria = spec
        rep = new_ele("filter", type=type)
        if type == "xpath":
            rep.attrib["select"] = criteria
        elif type == "subtree":
            rep.append(to_ele(criteria))
        else:
            raise OperationError("Invalid filter type")
    else:
        rep = validated_element(spec, ("filter", qualify("filter")),
                                        attrs=("type",))
        # TODO set type var here, check if select attr present in case of xpath..
    if type == "xpath" and capcheck is not None:
        capcheck(":xpath")
    return rep
