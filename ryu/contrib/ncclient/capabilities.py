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

def _abbreviate(uri):
    if uri.startswith("urn:ietf:params") and ":netconf:" in uri:
        splitted = uri.split(":")
        if ":capability:" in uri:
            if uri.startswith("urn:ietf:params:xml:ns:netconf"):
                name, version = splitted[7], splitted[8]
            else:
                name, version = splitted[5], splitted[6]
            return [ ":" + name, ":" + name + ":" + version ]
        elif ":base:" in uri:
            if uri.startswith("urn:ietf:params:xml:ns:netconf"):
                return [ ":base", ":base" + ":" + splitted[7] ]
            else:
                return [ ":base", ":base" + ":" + splitted[5] ]
    return []

def schemes(url_uri):
    "Given a URI that has a *scheme* query string (i.e. `:url` capability URI), will return a list of supported schemes."
    return url_uri.partition("?scheme=")[2].split(",")

class Capabilities:

    "Represents the set of capabilities available to a NETCONF client or server. It is initialized with a list of capability URI's."
    
    def __init__(self, capabilities):
        self._dict = {}
        for uri in capabilities:
            self._dict[uri] = _abbreviate(uri)

    def __contains__(self, key):
        if key in self._dict:
            return True
        for abbrs in self._dict.values():
            if key in abbrs:
                return True
        return False

    def __len__(self):
        return len(self._dict)

    def __iter__(self):
        return self._dict.iterkeys()

    def __repr__(self):
        return repr(self._dict.keys())

    def add(self, uri):
        "Add a capability."
        self._dict[uri] = _abbreviate(uri)

    def remove(self, uri):
        "Remove a capability."
        if key in self._dict:
            del self._dict[key]