import logging
import traceback

from ryu.lib.packet.bgp import RouteFamily
from ryu.lib.packet.bgp import RF_IPv4_UC
from ryu.lib.packet.bgp import RF_IPv6_UC
from ryu.lib.packet.bgp import RF_IPv4_VPN
from ryu.lib.packet.bgp import RF_IPv6_VPN
from ryu.lib.packet.bgp import RF_L2_EVPN
from ryu.lib.packet.bgp import RF_RTC_UC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MULTI_EXIT_DISC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_LOCAL_PREF
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_IGP
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_EGP
from ryu.lib.packet.bgp import BGP_ATTR_ORIGIN_INCOMPLETE

from ryu.services.protocols.bgp.base import add_bgp_error_metadata
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.base import SUPPORTED_GLOBAL_RF
from ryu.services.protocols.bgp.core_manager import CORE_MANAGER


LOG = logging.getLogger('bgpspeaker.operator.internal_api')

INTERNAL_API_ERROR = 100
INTERNAL_API_SUB_ERROR = 101


class InternalApi(object):

    def __init__(self, log_handler=None):
        self.log_handler = log_handler

    def count_all_vrf_routes(self):
        vrf_tables = self._get_vrf_tables()
        ret = {}
        for key in vrf_tables.keys():
            vrf_name, vrf_rf = key
            ret.update(self.count_single_vrf_routes(vrf_name, vrf_rf))
        return ret

    def count_single_vrf_routes(self, vrf_name, vrf_rf):
        vrf = self._get_vrf_tables().get((vrf_name, vrf_rf))
        if vrf is None:
            raise WrongParamError('wrong vpn key %s' % str((vrf_name, vrf_rf)))
        vrf_name = vrf_name.encode('ascii', 'ignore')

        route_count = \
            len([d for d in vrf.values() if d.best_path])
        return {str((vrf_name, vrf_rf)): route_count}

    def get_vrfs_conf(self):
        return CORE_MANAGER.vrfs_conf.vrfs_by_rd_rf_id

    def get_all_vrf_routes(self):
        vrfs = self._get_vrf_tables()
        ret = {}
        for (vrf_id, vrf_rf), table in sorted(vrfs.items()):
            ret[str((vrf_id, vrf_rf))] = self._get_single_vrf_routes(table)
        return ret

    def get_single_vrf_routes(self, vrf_id, vrf_rf):
        vrf = self._get_vrf_table(vrf_id, vrf_rf)
        if not vrf:
            raise WrongParamError('wrong vpn name %s' % str((vrf_id, vrf_rf)))
        return [self._dst_to_dict(d) for d in vrf.values()]

    def _get_single_vrf_routes(self, vrf_table):
        return [self._dst_to_dict(d) for d in vrf_table.values()]

    def _get_vrf_table(self, vrf_name, vrf_rf):
        return CORE_MANAGER.get_core_service()\
            .table_manager.get_vrf_table(vrf_name, vrf_rf)

    def _get_vrf_tables(self):
        return CORE_MANAGER.get_core_service().table_manager.get_vrf_tables()

    def get_single_rib_routes(self, addr_family):
        rfs = {
            'ipv4': RF_IPv4_UC,
            'ipv6': RF_IPv6_UC,
            'vpnv4': RF_IPv4_VPN,
            'vpnv6': RF_IPv6_VPN,
            'evpn': RF_L2_EVPN,
            'rtfilter': RF_RTC_UC
        }
        if addr_family not in rfs:
            raise WrongParamError('Unknown or unsupported family: %s' %
                                  addr_family)

        rf = rfs.get(addr_family)
        table_manager = self.get_core_service().table_manager
        gtable = table_manager.get_global_table_by_route_family(rf)
        if gtable is not None:
            return [self._dst_to_dict(dst)
                    for dst in sorted(gtable.values())]
        else:
            return []

    def _dst_to_dict(self, dst):
        ret = {'paths': [],
               'prefix': dst.nlri_str}

        def _path_to_dict(dst, path):

            path_seg_list = path.get_pattr(BGP_ATTR_TYPE_AS_PATH).path_seg_list

            if isinstance(path_seg_list, list):
                aspath = []
                for as_path_seg in path_seg_list:
                    for as_num in as_path_seg:
                        aspath.append(as_num)
            else:
                aspath = ''

            origin = path.get_pattr(BGP_ATTR_TYPE_ORIGIN)
            origin = origin.value if origin else None

            if origin == BGP_ATTR_ORIGIN_IGP:
                origin = 'i'
            elif origin == BGP_ATTR_ORIGIN_EGP:
                origin = 'e'
            elif origin == BGP_ATTR_ORIGIN_INCOMPLETE:
                origin = '?'

            nexthop = path.nexthop
            # Get the MED path attribute
            med = path.get_pattr(BGP_ATTR_TYPE_MULTI_EXIT_DISC)
            med = med.value if med else ''
            # Get best path reason
            bpr = dst.best_path_reason if path == dst.best_path else ''

            # Get local preference
            localpref = path.get_pattr(BGP_ATTR_TYPE_LOCAL_PREF)
            localpref = localpref.value if localpref else ''

            if hasattr(path.nlri, 'label_list'):
                labels = path.nlri.label_list
            else:
                labels = None

            return {'best': (path == dst.best_path),
                    'bpr': bpr,
                    'prefix': path.nlri_str,
                    'labels': labels,
                    'nexthop': nexthop,
                    'metric': med,
                    'aspath': aspath,
                    'origin': origin,
                    'localpref': localpref}

        for path in dst.known_path_list:
            ret['paths'].append(_path_to_dict(dst, path))

        return ret

    def check_logging(self):
        return self.log_handler and self._has_log_handler(self.log_handler)

    def check_logging_level(self):
        return logging.getLevelName(self.log_handler.level)

    def _has_log_handler(self, log_handler):
        if log_handler in logging.getLogger('bgpspeaker').handlers:
            return True
        return False

    def route_refresh(self, peer_ip=None, afi=None, safi=None):
        if not peer_ip:
            peer_ip = 'all'

        try:
            route_families = []
            if afi is None and safi is None:
                route_families.extend(SUPPORTED_GLOBAL_RF)
            else:
                route_family = RouteFamily(afi, safi)
                if route_family not in SUPPORTED_GLOBAL_RF:
                    raise WrongParamError('Not supported address-family'
                                          ' %s, %s' % (afi, safi))
                route_families.append(route_family)

            pm = CORE_MANAGER.get_core_service().peer_manager
            pm.make_route_refresh_request(peer_ip, *route_families)
        except Exception as e:
            LOG.error(traceback.format_exc())
            raise WrongParamError(str(e))
        return None

    def get_core_service(self):
        return CORE_MANAGER.get_core_service()


@add_bgp_error_metadata(code=INTERNAL_API_ERROR,
                        sub_code=INTERNAL_API_SUB_ERROR,
                        def_desc='Unknown internal api exception.')
class WrongParamError(BGPSException):
    pass
