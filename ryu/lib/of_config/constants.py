# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at valinux co jp>
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

# based on of-config-1.1.1.xsd

# commonly used
TYPE = 'type'
ID = 'id'
OPERATION = 'operation'
PORT = 'port'
PROTOCOL = 'protocol'

# of-configuration-point-protocol
SSH = 'ssh'
SOAP = 'soap'
TLS = 'tls'
BEEP = 'beep'

# of-open-flow-version
VERSION = 'version'
NOT_APPLICABLE = 'not-applicable'
OF_VERSION_1_0 = '1.0'
OF_VERSION_1_0_1 = '1.0.1'
OF_VERSION_1_1 = '1.1'
OF_VERSION_1_2 = '1.2'
OF_VERSION_1_3 = '1.3'
OF_VERSION_1_3_1 = '1.3.1'

# of-up-down-state
UP = 'up'
DOWN = 'down'

# of-port-rate
PORT_RATE_10MB_HD = '10Mb-HD'
PORT_RATE_10MB_FD = '10Mb-FD'
PORT_RATE_100MB_HD = '100Mb-HD'
PORT_RATE_100MB_FD = '100Mb-FD'
PORT_RATE_1GB_HD = '1Gb-HD'
PORT_RATE_1GB_FD = '1Gb-FD'
PORT_RATE_10GB = '10Gb'
PORT_RATE_40GB = '40Gb'
PORT_RATE_100GB = '100Gb'
PORT_RATE_1TB = '1 Tb'
PORT_RATE_1TB_ = '1Tb'          # of-config-1.1.1.xsd uses non space version
                                # to be checked after of-config 1.1.1 is
                                # publicly release
PORT_RATE_OTHER = 'Other'
PORT_RATE_other = 'other'       # of-config-1.1.1 uses lower case.
                                # to be checked after of-config 1.1.1 is
                                # publicly release

# of-action
OUTPUT = 'output'
COPY_TTL_OUT = 'copy-ttl-out'
COPY_TTL_IN = 'copy-ttl-in'
SET_MPLS_TTL = 'set-mpls-ttl'
DEC_MPLS_TTL = 'dec-mpls-ttl'
PUSH_VLAN = 'push-vlan'
POP_VLAN = 'pop-vlan'
PUSH_MPLS = 'push-mpls'
POP_MPLS = 'pop-mpls'
SET_QUEUE = 'set-queue'
GROUP = 'group'
SET_NW_TTL = 'set-nw-ttl'
DEC_NW_TTL = 'dec-nw-ttl'
SET_FIELD = 'set-field'

# of-instruction
APPLY_ACTIONS = 'apply-actions'
CLEAR_ACTIONS = 'clear-actions'
WRITE_ACTIONS = 'write-actions'
WRITE_METADATA = 'write-metadata'
GOTO_TABLE = 'goto-table'

# of-match-field
INPUT_PORT = 'input-port'
PHYSICAL_INPUT_PORT = 'physical-input-port'
METADATA = 'metadata'
ETHERNET_DEST = 'ethernet-dest'
ETHERNET_SRC = 'ethernet-src'
ETHERNET_FRAME_TYPE = 'ethernet-frame-type'
VLAN_ID = 'vlan-id'
VLAN_PRIORITY = 'vlan-priority'
IP_DSCP = 'ip-dscp'
IP_ECN = 'ip-ecn'
IP_PROTOCOL = 'ip-protocol'
IPV4_SRC = 'ipv4-src'
IPV4_DEST = 'ipv4-dest'
TCP_SRC = 'tcp-src'
TCP_DEST = 'tcp-dest'
UDP_SRC = 'udp-src'
UDP_DEST = 'udp-dest'
SCTP_SRC = 'sctp-src'
SCTP_DEST = 'sctp-dest'
ICMPV4_TYPE = 'icmpv4-type'
ICMPV4_CODE = 'icmpv4-code'
ARP_OP = 'arp-op'
ARP_SRC_IP_ADDRESS = 'arp-src-ip-address'
ARP_TARGET_IP_ADDRESS = 'arp-target-ip-address'
ARP_SRC_HARDWARE_ADDRESS = 'arp-src-hardware-address'
ARP_TARGET_HARDWARE_ADDRESS = 'arp-target-hardware-address'
IPV6_SRC = 'ipv6-src'
IPV6_DEST = 'ipv6-dest'
IPV6_FLOW_LABEL = 'ipv6-flow-label'
ICMPV6_TYPE = 'icmpv6-type'
ICMPV6_CODE = 'icmpv6-code'
IPV6_ND_TARGET = 'ipv6-nd-target'
IPV6_ND_SOURCE_LINK_LAYER = 'ipv6-nd-source-link-layer'
IPV6_ND_TARGET_LINK_LAYER = 'ipv6-nd-target-link-layer'
MPLS_LABEL = 'mpls-label'
MPLS_TC = 'mpls-tc'

# of-port-current-feature-list and of-port-other-feature-list
RATE = 'rate'
AUTO_NEGOTIATE = 'auto-negotiate'
MEDIUM = 'medium'
COPPER = 'copper'
FIBER = 'fiber'
PAUSE = 'pause'
UNSUPPORTED = 'unsupported'
SYMMETRIC = 'symmetric'
ASYMMETRIC = 'asymmetric'

# DSA-key-value
DSA_KEY_VALUE_P = 'P'
DSA_KEY_VALUE_Q = 'Q'
DSA_KEY_VALUE_J = 'J'
DSA_KEY_VALUE_G = 'G'
DSA_KEY_VALUE_Y = 'Y'
DSA_KEY_VALUE_SEED = 'Seed'
DSA_KEY_VALUE_PGENCOUNTER = 'PgenCounter'

# of-port-base-tunnel
LOCAL_ENDPOINT_IPV4_ADDRESS = 'local-endpoint-ipv4-address'
REMOTE_ENDPOINT_IPV4_ADDRESS = 'remote-endpoint-ipv4-address'
LOCAL_ENDPOINT_IPV6_ADDRESS = 'local-endpoint-ipv6-address'
REMOTE_ENDPOINT_IPV6_ADDRESS = 'remote-endpoint-ipv6-address'
LOCAL_ENDPOINT_MAC_ADRESS = 'local-endpoint-mac-adress'
REMOTE_ENDPOINT_MAC_ADRESS = 'remote-endpoint-mac-adress'

# of-port-ip-gre-tunnel
CHECKSUM_PRESENT = 'checksum-present'
KEY_PRESENT = 'key-present'
KEY = 'key'
SEQUENCE_NUMBER_PRESENT = 'sequence-number-present'

# of-port-nvgre-tunnel
TNI = 'tni'
TNI_RESV = 'tni-resv'
TNI_MULTICAST_GROUP = 'tni-multicast-group'

# of-queue
# ID = 'id'
# PORT = 'port'
PROPERTIES = 'properties'
MIN_RATE = 'min-rate'
MAX_RATE = 'max-rate'
EXPERIMENTER = 'experimenter'

# of-owned-certificate and of-external-certificate
CERTIFICATE = 'certificate'
PRIVATE_KEY = 'private-key'

# of-configuration-point
# ID = 'id'
URI = 'uri'
# PROTOCOL = 'protocol'

# rsa-key-value
MODULUS = 'Modulus'
EXPONENT = 'Exponent'

# of-flow-table
MAX_ENTRIES = 'max-entries'
NEXT_TABLES = 'next-tables'
TABLE_ID = 'table-id'
INSTRUCTIONS = 'instructions'
# TYPE = 'type'
MATCHES = 'matches'
# TYPE = 'type'
# WRITE_ACTIONS = 'write-actions'
# TYPE = 'type'
# APPLY_ACTIONS = 'apply-actions'
# TYPE = 'type'
# WRITE_SETFIELDS = 'write-setfields'
# TYPE = 'type'
# APPLY_SETFIELDS = 'apply-setfields'
# TYPE = 'type'
WILDCARDS = 'wildcards'
# TYPE = 'type'
METADATA_MATCH = 'metadata-match'
METADATA_WRITE = 'metadata-write'

# of-logical-switch
# ID = 'id'
CAPABILITIES = 'capabilities'
DATAPATH_ID = 'datapath-id'
ENABLED = 'enabled'
CHECK_CONTROLLER_CERTIFICATE = 'check-controller-certificate'
LOST_CONNECTION_BEHAVIOR = 'lost-connection-behavior'
FAILSECUREMODE = 'failSecureMode'
FAILSTANDALONEMODE = 'failStandaloneMode'
CONTROLLERS = 'controllers'
CONTROLLER = 'controller'
# OPERATION = 'operation'
KEY_CONTROLLERS_CONTROLLER = 'key_controllers_controller'
RESOURCES = 'resources'
# PORT = 'port'
QUEUE = 'queue'
# CERTIFICATE = 'certificate'
# FLOW_TABLE = 'flow-table'

# key-value
DSAKEYVALUE = 'DSAKeyValue'
RSAKEYVALUE = 'RSAKeyValue'

# of-logical-switch-capabilities
MAX_BUFFERED_PACKETS = 'max-buffered-packets'
MAX_TABLES = 'max-tables'
MAX_PORTS = 'max-ports'
FLOW_STATISTICS = 'flow-statistics'
TABLE_STATISTICS = 'table-statistics'
# PORT_STATISTICS = 'port-statistics'
GROUP_STATISTICS = 'group-statistics'
QUEUE_STATISTICS = 'queue-statistics'
REASSEMBLE_IP_FRAGMENTS = 'reassemble-ip-fragments'
BLOCK_LOOPING_PORTS = 'block-looping-ports'
RESERVED_PORT_TYPES = 'reserved-port-types'
# TYPE = 'type'
ALL = 'all'
# CONTROLLER = 'controller'
TABLE = 'table'
INPORT = 'inport'
ANY = 'any'
NORMAL = 'normal'
FLOOD = 'flood'
GROUP_TYPES = 'group-types'
# TYPE = 'type'
# ALL = 'all'
SELECT = 'select'
INDIRECT = 'indirect'
FAST_FAILOVER = 'fast-failover'
GROUP_CAPABILITIES = 'group-capabilities'
CAPABILITY = 'capability'
SELECT_WEIGHT = 'select-weight'
SELECT_LIVENESS = 'select-liveness'
CHAINING = 'chaining'
CHAINING_CHECK = 'chaining-check'
ACTION_TYPES = 'action-types'
# TYPE = 'type'
INSTRUCTION_TYPES = 'instruction-types'
# TYPE = 'type'

# of-port
NUMBER = 'number'
NAME = 'name'
CURRENT_RATE = 'current-rate'
# MAX_RATE = 'max-rate'
CONFIGURATION = 'configuration'
ADMIN_STATE = 'admin-state'
NO_RECEIVE = 'no-receive'
NO_FORWARD = 'no-forward'
NO_PACKET_IN = 'no-packet-in'
# OPERATION = 'operation'
STATE = 'state'
OPER_STATE = 'oper-state'
BLOCKED = 'blocked'
LIVE = 'live'
FEATURES = 'features'
CURRENT = 'current'
ADVERTISED = 'advertised'
# OPERATION = 'operation'
SUPPORTED = 'supported'
ADVERTISED_PEER = 'advertised-peer'
TUNNEL = 'tunnel'
IPGRE_TUNNEL = 'ipgre-tunnel'
VXLAN_TUNNEL = 'vxlan-tunnel'
NVGRE_TUNNEL = 'nvgre-tunnel'

# of-resource
RESOURCE_ID = 'resource-id'

# of-port-vxlan-tunnel
VNI_VALID = 'vni-valid'
VNI = 'vni'
VNI_MULTICAST_GROUP = 'vni-multicast-group'
UDP_SOURCE_PORT = 'udp-source-port'
UDP_DEST_PORT = 'udp-dest-port'
UDP_CHECKSUM = 'udp-checksum'

# of-controller
# ID = 'id'
ROLE = 'role'
MASTER = 'master'
SLAVE = 'slave'
EQUAL = 'equal'
IP_ADDRESS = 'ip-address'
# PORT = 'port'
LOCAL_IP_ADDRESS = 'local-ip-address'
LOCAL_PORT = 'local-port'
# PROTOCOL = 'protocol'
TCP = 'tcp'
# TLS = 'tls'
# STATE = 'state'
CONNECTION_STATE = 'connection-state'
CURRENT_VERSION = 'current-version'
SUPPORTED_VERSIONS = 'supported-versions'
LOCAL_IP_ADDRESS_IN_USE = 'local-ip-address-in-use'
LOCAL_PORT_IN_USE = 'local-port-in-use'
CAPABLE_SWITCH = 'capable-switch'
# ID = 'id'
CONFIG_VERSION = 'config-version'
CONFIGURATION_POINTS = 'configuration-points'
CONFIGURATION_POINT = 'configuration-point'
KEY_CONFIGURATION_POINTS_CAPABLESWITCH_CONFIGURATION_POINT = (
    'key_configuration-points_capableswitch_configuration-point')
# RESOURCES = 'resources'
# PORT = 'port'
# QUEUE = 'queue'
# OPERATION = 'operation'
OWNED_CERTIFICATE = 'owned-certificate'
EXTERNAL_CERTIFICATE = 'external-certificate'
# OPERATION = 'operation'
FLOW_TABLE = 'flow-table'
KEY_RESOURCES_CAPABLE_SWITCH_PORT = 'key_resources_capable-switch_port'
KEY_RESOURCES_CAPABLE_SWITCH_QUEUE = 'key_resources_capable-switch_queue'
KEY_RESOURCES_CAPABLE_SWITCH_OWNED_CERTIFICATE = (
    'key_resources_capable-switch_owned-certificate')
KEY_RESOURCES_CAPABLE_SWITCH_EXTERNAL_CERTIFICATE = (
    'key_resources_capable-switch_external-certificate')
KEY_RESOURCES_CAPABLE_SWITCH_FLOW_TABLE = (
    'key_resources_capable-switch_flow-table')
LOGICAL_SWITCHES = 'logical-switches'
SWITCH = 'switch'
KEY_LOGICAL_SWITCHES_CAPABLE_SWITCH_SWITCH = (
    'key_logical-switches_capable-switch_switch')
