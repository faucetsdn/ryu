
from __future__ import absolute_import

import os

from ryu.services.protocols.bgp.bgpspeaker import RF_VPN_V4
from ryu.services.protocols.bgp.bgpspeaker import RF_VPN_V6
from ryu.services.protocols.bgp.bgpspeaker import RF_L2_EVPN
from ryu.services.protocols.bgp.bgpspeaker import RF_VPNV4_FLOWSPEC
from ryu.services.protocols.bgp.bgpspeaker import RF_VPNV6_FLOWSPEC
from ryu.services.protocols.bgp.bgpspeaker import RF_L2VPN_FLOWSPEC
from ryu.services.protocols.bgp.bgpspeaker import EVPN_MAX_ET
from ryu.services.protocols.bgp.bgpspeaker import ESI_TYPE_LACP
from ryu.services.protocols.bgp.bgpspeaker import ESI_TYPE_MAC_BASED
from ryu.services.protocols.bgp.bgpspeaker import EVPN_ETH_AUTO_DISCOVERY
from ryu.services.protocols.bgp.bgpspeaker import EVPN_MAC_IP_ADV_ROUTE
from ryu.services.protocols.bgp.bgpspeaker import TUNNEL_TYPE_VXLAN
from ryu.services.protocols.bgp.bgpspeaker import EVPN_MULTICAST_ETAG_ROUTE
from ryu.services.protocols.bgp.bgpspeaker import EVPN_ETH_SEGMENT
from ryu.services.protocols.bgp.bgpspeaker import EVPN_IP_PREFIX_ROUTE
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_FAMILY_IPV4
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_FAMILY_IPV6
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_FAMILY_VPNV4
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_FAMILY_VPNV6
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_FAMILY_L2VPN
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_TA_SAMPLE
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_TA_TERMINAL
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_VLAN_POP
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_VLAN_PUSH
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_VLAN_SWAP
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_VLAN_RW_INNER
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_VLAN_RW_OUTER
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_TPID_TI
from ryu.services.protocols.bgp.bgpspeaker import FLOWSPEC_TPID_TO
from ryu.services.protocols.bgp.bgpspeaker import REDUNDANCY_MODE_SINGLE_ACTIVE

# =============================================================================
# BGP configuration.
# =============================================================================
BGP = {

    # AS number for this BGP instance.
    'local_as': 65001,

    # BGP Router ID.
    'router_id': '172.17.0.1',

    # Default local preference
    'local_pref': 100,

    # List of TCP listen host addresses.
    'bgp_server_hosts': ['0.0.0.0', '::'],

    # List of BGP neighbors.
    # The parameters for each neighbor are the same as the arguments of
    # BGPSpeaker.neighbor_add() method.
    'neighbors': [
        {
            'address': '172.17.0.2',
            'remote_as': 65002,
            'enable_ipv4': True,
            'enable_ipv6': True,
            'enable_vpnv4': True,
            'enable_vpnv6': True,
        },
        {
            'address': '172.17.0.3',
            'remote_as': 65001,
            'enable_evpn': True,
        },
        {
            'address': '172.17.0.4',
            'remote_as': 65001,
            'enable_ipv4fs': True,
            'enable_ipv6fs': True,
            'enable_vpnv4fs': True,
            'enable_vpnv6fs': True,
            'enable_l2vpnfs': True,
        },
    ],

    # List of BGP VRF tables.
    # The parameters for each VRF table are the same as the arguments of
    # BGPSpeaker.vrf_add() method.
    'vrfs': [
        # Example of VRF for IPv4
        {
            'route_dist': '65001:100',
            'import_rts': ['65001:100'],
            'export_rts': ['65001:100'],
            'route_family': RF_VPN_V4,
        },
        # Example of VRF for IPv6
        {
            'route_dist': '65001:150',
            'import_rts': ['65001:150'],
            'export_rts': ['65001:150'],
            'route_family': RF_VPN_V6,
        },
        # Example of VRF for EVPN
        {
            'route_dist': '65001:200',
            'import_rts': ['65001:200'],
            'export_rts': ['65001:200'],
            'route_family': RF_L2_EVPN,
        },
        # Example of VRF for IPv4 FlowSpec
        {
            'route_dist': '65001:250',
            'import_rts': ['65001:250'],
            'export_rts': ['65001:250'],
            'route_family': RF_VPNV4_FLOWSPEC,
        },
        # Example of VRF for IPv6 FlowSpec
        {
            'route_dist': '65001:300',
            'import_rts': ['65001:300'],
            'export_rts': ['65001:300'],
            'route_family': RF_VPNV6_FLOWSPEC,
        },
        # Example of VRF for L2VPN FlowSpec
        {
            'route_dist': '65001:350',
            'import_rts': ['65001:350'],
            'export_rts': ['65001:350'],
            'route_family': RF_L2VPN_FLOWSPEC,
        },
    ],

    # List of BGP routes.
    # The parameters for each route are the same as the arguments of
    # the following methods:
    # - BGPSpeaker.prefix_add()
    # - BGPSpeaker.evpn_prefix_add()
    # - BGPSpeaker.flowspec_prefix_add()
    'routes': [
        # Example of IPv4 prefix
        {
            'prefix': '10.10.1.0/24',
        },
        # Example of VPNv4 prefix
        {
            'prefix': '10.20.1.0/24',
            'next_hop': '172.17.0.1',
            'route_dist': '65001:100',
        },
        # Example of IPv6 prefix
        {
            'prefix': '2001:db8:1::/64',
        },
        # Example of VPNv6 prefix
        {
            'prefix': '2001:db8:2::/64',
            'next_hop': '172.17.0.1',
            'route_dist': '65001:150',
        },
        # Example of EVPN prefix
        {
            'route_type': EVPN_ETH_AUTO_DISCOVERY,
            'route_dist': '65001:200',
            'esi': {
                'type': ESI_TYPE_LACP,
                'mac_addr': 'aa:bb:cc:dd:ee:ff',
                'port_key': 100,
            },
            'ethernet_tag_id': EVPN_MAX_ET,
            'redundancy_mode': REDUNDANCY_MODE_SINGLE_ACTIVE,
        },
        {
            'route_type': EVPN_MAC_IP_ADV_ROUTE,
            'route_dist': '65001:200',
            'esi': 0,
            'ethernet_tag_id': 0,
            'tunnel_type': TUNNEL_TYPE_VXLAN,
            'vni': 200,
            'mac_addr': 'aa:bb:cc:dd:ee:ff',
            'ip_addr': '10.30.1.1',
            'next_hop': '172.17.0.1',
        },
        {
            'route_type': EVPN_MULTICAST_ETAG_ROUTE,
            'route_dist': '65001:200',
            'esi': 0,
            'ethernet_tag_id': 0,
            'ip_addr': '10.40.1.1',
        },
        {
            'route_type': EVPN_ETH_SEGMENT,
            'route_dist': '65001:200',
            'esi': {
                'type': ESI_TYPE_MAC_BASED,
                'mac_addr': 'aa:bb:cc:dd:ee:ff',
                'local_disc': 100,
            },
            'ip_addr': '172.17.0.1',
        },
        {
            'route_type': EVPN_IP_PREFIX_ROUTE,
            'route_dist': '65001:200',
            'esi': 0,
            'ethernet_tag_id': 0,
            'ip_prefix': '10.50.1.0/24',
            'gw_ip_addr': '172.16.0.1',
        },
        # Example of Flow Specification IPv4 prefix
        {
            'flowspec_family': FLOWSPEC_FAMILY_IPV4,
            'rules': {
                'dst_prefix': '10.60.1.0/24',
                'src_prefix': '172.17.0.0/24',
                'ip_proto': 6,
                'port': '80 | 8000',
                'dst_port': '>9000 & <9050',
                'src_port': '>=8500 & <=9000',
                'icmp_type': 0,
                'icmp_code': 6,
                'tcp_flags': 'SYN+ACK & !=URGENT',
                'packet_len': 1000,
                'dscp': '22 | 24',
                'fragment': 'LF | ==FF',
            },
            'actions': {
                'traffic_rate': {
                    'as_number': 0,
                    'rate_info': 100.0,
                },
                'traffic_action': {
                    'action': FLOWSPEC_TA_SAMPLE | FLOWSPEC_TA_TERMINAL,
                },
                'redirect': {
                    'as_number': 10,
                    'local_administrator': 100,
                },
                'traffic_marking': {
                    'dscp': 24,
                }
            },
        },
        # Example of Flow Specification VPNv4 prefix
        {
            'flowspec_family': FLOWSPEC_FAMILY_VPNV4,
            'route_dist': '65001:250',
            'rules': {
                'dst_prefix': '10.70.1.0/24',
                'src_prefix': '172.18.0.0/24',
                'ip_proto': 6,
                'port': '80 | 8000',
                'dst_port': '>9000 & <9050',
                'src_port': '>=8500 & <=9000',
                'icmp_type': 0,
                'icmp_code': 6,
                'tcp_flags': 'SYN+ACK & !=URGENT',
                'packet_len': 1000,
                'dscp': '22 | 24',
                'fragment': 'LF | ==FF',
            },
            'actions': {
                'traffic_rate': {
                    'as_number': 0,
                    'rate_info': 100.0,
                },
                'traffic_action': {
                    'action': FLOWSPEC_TA_SAMPLE | FLOWSPEC_TA_TERMINAL,
                },
                'redirect': {
                    'as_number': 10,
                    'local_administrator': 100,
                },
                'traffic_marking': {
                    'dscp': 24,
                }
            },
        },
        # Example of Flow Specification IPv6 prefix
        {
            'flowspec_family': FLOWSPEC_FAMILY_IPV6,
            'rules': {
                'dst_prefix': '2001::1/128/32',
                'src_prefix': '3001::2/128',
                'next_header': 6,
                'port': '80 | 8000',
                'dst_port': '>9000 & <9050',
                'src_port': '>=8500 & <=9000',
                'icmp_type': 0,
                'icmp_code': 6,
                'tcp_flags': 'SYN+ACK & !=URGENT',
                'packet_len': 1000,
                'dscp': '22 | 24',
                'fragment': 'LF | ==FF',
                'flow_label': 100,
            },
            'actions': {
                'traffic_rate': {
                    'as_number': 0,
                    'rate_info': 100.0,
                },
                'traffic_action': {
                    'action': FLOWSPEC_TA_SAMPLE | FLOWSPEC_TA_TERMINAL,
                },
                'redirect': {
                    'as_number': 10,
                    'local_administrator': 100,
                },
                'traffic_marking': {
                    'dscp': 24,
                }
            },
        },
        # Example of Flow Specification VPNv6 prefix
        {
            'flowspec_family': FLOWSPEC_FAMILY_VPNV6,
            'route_dist': '65001:300',
            'rules': {
                'dst_prefix': '2001::1/128/32',
                'src_prefix': '3001::2/128',
                'next_header': 6,
                'port': '80 | 8000',
                'dst_port': '>9000 & <9050',
                'src_port': '>=8500 & <=9000',
                'icmp_type': 0,
                'icmp_code': 6,
                'tcp_flags': 'SYN+ACK & !=URGENT',
                'packet_len': 1000,
                'dscp': '22 | 24',
                'fragment': 'LF | ==FF',
                'flow_label': 100,
            },
            'actions': {
                'traffic_rate': {
                    'as_number': 0,
                    'rate_info': 100.0,
                },
                'traffic_action': {
                    'action': FLOWSPEC_TA_SAMPLE | FLOWSPEC_TA_TERMINAL,
                },
                'redirect': {
                    'as_number': 10,
                    'local_administrator': 100,
                },
                'traffic_marking': {
                    'dscp': 24,
                }
            },
        },
        # Example of Flow Specification L2VPN prefix
        {
            'flowspec_family': FLOWSPEC_FAMILY_L2VPN,
            'route_dist': '65001:350',
            'rules': {
                'ether_type': 0x0800,
                'src_mac': '12:34:56:78:90:AB',
                'dst_mac': 'BE:EF:C0:FF:EE:DD',
                'llc_dsap': 0x42,
                'llc_ssap': 0x42,
                'llc_control': 100,
                'snap': 0x12345,
                'vlan_id': '>4000',
                'vlan_cos': '>=3',
                'inner_vlan_id': '<3000',
                'inner_vlan_cos': '<=5',
            },
            'actions': {
                'traffic_rate': {
                    'as_number': 0,
                    'rate_info': 100.0,
                },
                'traffic_action': {
                    'action': FLOWSPEC_TA_SAMPLE | FLOWSPEC_TA_TERMINAL,
                },
                'redirect': {
                    'as_number': 10,
                    'local_administrator': 100,
                },
                'traffic_marking': {
                    'dscp': 24,
                },
                'vlan_action': {
                    'actions_1': FLOWSPEC_VLAN_POP | FLOWSPEC_VLAN_PUSH,
                    'vlan_1': 3000,
                    'cos_1': 3,
                    'actions_2': FLOWSPEC_VLAN_SWAP,
                    'vlan_2': 4000,
                    'cos_2': 2,
                },
                'tpid_action': {
                    'actions': FLOWSPEC_TPID_TI | FLOWSPEC_TPID_TO,
                    'tpid_1': 200,
                    'tpid_2': 300,
                }
            },
        }
    ],
}


# =============================================================================
# SSH server configuration.
# =============================================================================
SSH = {
    'ssh_port': 4990,
    'ssh_host': 'localhost',
    # 'ssh_host_key': '/etc/ssh_host_rsa_key',
    # 'ssh_username': 'ryu',
    # 'ssh_password': 'ryu',
}


# =============================================================================
# Logging configuration.
# =============================================================================
LOGGING = {

    # We use python logging package for logging.
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s ' +
                      '[%(process)d %(thread)d] %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(asctime)s %(module)s %(lineno)s ' +
                      '%(message)s'
        },
        'stats': {
            'format': '%(message)s'
        },
    },

    'handlers': {
        # Outputs log to console.
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'console_stats': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'stats'
        },
        # Rotates log file when its size reaches 10MB.
        'log_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('.', 'bgpspeaker.log'),
            'maxBytes': '10000000',
            'formatter': 'verbose'
        },
        'stats_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('.', 'statistics_bgps.log'),
            'maxBytes': '10000000',
            'formatter': 'stats'
        },
    },

    # Fine-grained control of logging per instance.
    'loggers': {
        'bgpspeaker': {
            'handlers': ['console', 'log_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'stats': {
            'handlers': ['stats_file', 'console_stats'],
            'level': 'INFO',
            'propagate': False,
            'formatter': 'stats',
        },
    },

    # Root loggers.
    'root': {
        'handlers': ['console', 'log_file'],
        'level': 'DEBUG',
        'propagate': True,
    },
}
