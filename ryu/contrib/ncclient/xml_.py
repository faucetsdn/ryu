# Copyright 2009 Shikhar Bhushan
# Copyright 2011 Leonidas Poulopoulos
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

"Methods for creating, parsing, and dealing with XML and ElementTree objects."

from cStringIO import StringIO
from xml.etree import cElementTree as ET

# In case issues come up with XML generation/parsing
# make sure you have the ElementTree v1.2.7+ lib

from ncclient import NCClientError

class XMLError(NCClientError): pass

### Namespace-related

#: Base NETCONF namespace
BASE_NS_1_0 = "urn:ietf:params:xml:ns:netconf:base:1.0"
#: Namespace for Tail-f core data model
TAILF_AAA_1_1 = "http://tail-f.com/ns/aaa/1.1"
#: Namespace for Tail-f execd data model
TAILF_EXECD_1_1 = "http://tail-f.com/ns/execd/1.1"
#: Namespace for Cisco data model
CISCO_CPI_1_0 = "http://www.cisco.com/cpi_10/schema"
#: Namespace for Flowmon data model
FLOWMON_1_0 = "http://www.liberouter.org/ns/netopeer/flowmon/1.0"
#: Namespace for Juniper 9.6R4. Tested with Junos 9.6R4+
JUNIPER_1_1 = "http://xml.juniper.net/xnm/1.1/xnm"
#
try:
    register_namespace = ET.register_namespace
except AttributeError:
    def register_namespace(prefix, uri):
        from xml.etree import ElementTree
        # cElementTree uses ElementTree's _namespace_map, so that's ok
        ElementTree._namespace_map[uri] = prefix
register_namespace.func_doc = "ElementTree's namespace map determines the prefixes for namespace URI's when serializing to XML. This method allows modifying this map to specify a prefix for a namespace URI."

for (ns, pre) in {
    BASE_NS_1_0: 'nc',
    TAILF_AAA_1_1: 'aaa',
    TAILF_EXECD_1_1: 'execd',
    CISCO_CPI_1_0: 'cpi',
    FLOWMON_1_0: 'fm',
    JUNIPER_1_1: 'junos',
}.items(): 
    register_namespace(pre, ns)

qualify = lambda tag, ns=BASE_NS_1_0: tag if ns is None else "{%s}%s" % (ns, tag)
"""Qualify a *tag* name with a *namespace*, in :mod:`~xml.etree.ElementTree` fashion i.e. *{namespace}tagname*."""

def to_xml(ele, encoding="UTF-8"):
    "Convert and return the XML for an *ele* (:class:`~xml.etree.ElementTree.Element`) with specified *encoding*."
    xml = ET.tostring(ele, encoding)
    return xml if xml.startswith('<?xml') else '<?xml version="1.0" encoding="%s"?>%s' % (encoding, xml)

def to_ele(x):
    "Convert and return the :class:`~xml.etree.ElementTree.Element` for the XML document *x*. If *x* is already an :class:`~xml.etree.ElementTree.Element` simply returns that."
    return x if ET.iselement(x) else ET.fromstring(x)

def parse_root(raw):
    "Efficiently parses the root element of a *raw* XML document, returning a tuple of its qualified name and attribute dictionary."
    fp = StringIO(raw)
    for event, element in ET.iterparse(fp, events=('start',)):
        return (element.tag, element.attrib)

def validated_element(x, tags=None, attrs=None):
    """Checks if the root element of an XML document or Element meets the supplied criteria.
    
    *tags* if specified is either a single allowable tag name or sequence of allowable alternatives

    *attrs* if specified is a sequence of required attributes, each of which may be a sequence of several allowable alternatives

    Raises :exc:`XMLError` if the requirements are not met.
    """
    ele = to_ele(x)
    if tags:
        if isinstance(tags, basestring):
            tags = [tags]
        if ele.tag not in tags:
            raise XMLError("Element [%s] does not meet requirement" % ele.tag)
    if attrs:
        for req in attrs:
            if isinstance(req, basestring): req = [req]
            for alt in req:
                if alt in ele.attrib:
                    break
            else:
                raise XMLError("Element [%s] does not have required attributes" % ele.tag)
    return ele

new_ele = lambda tag, attrs={}, **extra: ET.Element(qualify(tag), attrs, **extra)

sub_ele = lambda parent, tag, attrs={}, **extra: ET.SubElement(parent, qualify(tag), attrs, **extra)

