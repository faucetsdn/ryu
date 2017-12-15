from ryu.services.protocols.bgp.operator.views.base import \
    create_dict_view_class
from ryu.services.protocols.bgp.operator.views.base import \
    create_list_view_class
from ryu.services.protocols.bgp.operator.views.base import OperatorDetailView
from ryu.services.protocols.bgp.operator.views import fields

from ryu.lib.packet.bgp import BGP_ATTR_TYPE_AS_PATH
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_ORIGIN
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_MULTI_EXIT_DISC
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_LOCAL_PREF
from ryu.lib.packet.bgp import BGP_ATTR_TYPE_EXTENDED_COMMUNITIES


class CoreServiceDetailView(OperatorDetailView):
    rf_state = fields.RelatedViewField(
        'rf_state',
        'ryu.services.protocols.bgp.operator.views.bgp.RfStateDetailView'
    )
    importmap_manager = fields.RelatedDictViewField(
        '_importmap_manager',
        'ryu.services.protocols.bgp.operator'
        '.views.other.ImportmapManagerDetailView'
    )
    table_manager = fields.RelatedViewField(
        '_table_manager',
        'ryu.services.protocols.bgp.operator.views.bgp.TableManagerDetailView'
    )
    peer_manager = fields.RelatedViewField(
        '_peer_manager',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerManagerDetailView'
    )
    router_id = fields.DataField('router_id')


class TableManagerDetailView(OperatorDetailView):
    tables = fields.RelatedDictViewField(
        '_tables',
        'ryu.services.protocols.bgp.operator.views.bgp.TableDictView'
    )
    tables_for_rt = fields.RelatedDictViewField(
        '_tables_for_rt',
        'ryu.services.protocols.bgp.operator.views.bgp.TableDictView'
    )
    global_tables = fields.RelatedDictViewField(
        '_global_tables',
        'ryu.services.protocols.bgp.operator.views.bgp.TableDictView'
    )
    asbr_label_range = fields.DataField('_asbr_label_range')
    next_hop_label = fields.DataField('_next_hop_label')
    next_vpnv4_label = fields.DataField('_next_vpnv4_label')


class PeerManagerDetailView(OperatorDetailView):
    peers = fields.RelatedListViewField(
        '_peers',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerDictView'
    )
    peers_summary = fields.RelatedListViewField(
        '_peers',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerDictSummaryView'
    )


class RfStateDetailView(OperatorDetailView):
    pass


class PeerStateDetailView(OperatorDetailView):
    bgp_state = fields.DataField('_bgp_state')
    last_error = fields.DataField('_last_bgp_error')

    def encode(self):
        ret = super(PeerStateDetailView, self).encode()
        ret.update(self._obj.get_stats_summary_dict())
        return ret


class PeerDetailView(OperatorDetailView):
    remote_as = fields.DataField('remote_as')
    ip_address = fields.DataField('ip_address')
    enabled = fields.DataField('enabled')
    adj_rib_in = fields.RelatedViewField(
        'adj_rib_in',
        'ryu.services.protocols.bgp.operator.views.bgp.ReceivedRouteDictView'
    )
    adj_rib_out = fields.RelatedViewField(
        'adj_rib_out',
        'ryu.services.protocols.bgp.operator.views.bgp.SentRouteDictView'
    )
    neigh_conf = fields.RelatedViewField(
        '_neigh_conf',
        'ryu.services.protocols.bgp.operator.views.conf.ConfDetailView'
    )
    common_conf = fields.RelatedViewField(
        '_common_conf',
        'ryu.services.protocols.bgp.operator.views.conf.ConfDetailView'
    )
    state = fields.RelatedViewField(
        'state',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerStateDetailView'
    )

    def encode(self):
        ret = super(PeerDetailView, self).encode()
        ret.update({
            'stats': self.rel('state').encode(),
            'settings': self.rel('neigh_conf').encode()
        })
        return ret


class PeerDetailSummaryView(PeerDetailView):
    def encode(self):
        return {
            'conf': self.rel('neigh_conf').encode(),
            'info': self.rel('state').encode()
        }


class PeerRfDetailView(OperatorDetailView):
    rf = fields.DataField('rf')
    enabled = fields.DataField('enabled')
    peer = fields.RelatedViewField(
        'peer',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerDetailView'
    )


class TableDetailView(OperatorDetailView):
    scope_id = fields.DataField('scope_id')
    route_family = fields.DataField('route_family')
    destinations = fields.RelatedDictViewField(
        '_destinations',
        'ryu.services.protocols.bgp.operator.views.bgp.DestinationDictView'
    )


class PathDetailView(OperatorDetailView):
    source_version_num = fields.DataField('source_version_num')
    route_family = fields.RelatedViewField(
        'route_family',
        'ryu.services.protocols.bgp.operator.views.bgp.RouteFamilyView'
    )
    nlri = fields.RelatedViewField(
        'nlri',
        'ryu.services.protocols.bgp.operator.views.bgp.NlriDetailView'
    )
    is_withdraw = fields.DataField('is_withdraw')
    nexthop = fields.DataField('nexthop')
    pathattr_map = fields.DataField('pathattr_map')
    source = fields.RelatedViewField(
        'source',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerDetailView'
    )

    def encode(self):
        ret = super(PathDetailView, self).encode()
        ret['nlri'] = self.rel('nlri').encode()
        ret['route_family'] = self.rel('route_family').encode()
        as_path = self.get_field('pathattr_map').get(BGP_ATTR_TYPE_AS_PATH)
        origin = self.get_field('pathattr_map').get(BGP_ATTR_TYPE_ORIGIN)
        metric = self.get_field('pathattr_map').get(
            BGP_ATTR_TYPE_MULTI_EXIT_DISC)
        local_pref = self.get_field('pathattr_map').get(
            BGP_ATTR_TYPE_LOCAL_PREF
        )

        ret['as_path'] = as_path.value if as_path else None
        ret['origin'] = origin.value if origin else None
        ret['metric'] = metric.value if metric else None
        ret['local_pref'] = local_pref.value if local_pref else None
        ext = ret['pathattr_map'].get(BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
        del ret['pathattr_map']
        if ext:
            ret['rt_list'] = ext.rt_list
            ret['soo_list'] = ext.soo_list
        return ret


class SentRouteDetailView(OperatorDetailView):
    timestamp = fields.DataField('timestamp')
    filtered = fields.DataField('filtered')
    path = fields.RelatedViewField(
        'path',
        'ryu.services.protocols.bgp.operator.views.bgp.PathDetailView',
    )
    peer = fields.RelatedViewField(
        'sent_peer',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerDetailView'
    )

    def encode(self):
        ret = super(SentRouteDetailView, self).encode()
        ret.update({
            'path': self.rel('path').encode(),
        })
        return ret


class ReceivedRouteDetailView(OperatorDetailView):
    timestamp = fields.DataField('timestamp')
    filtered = fields.DataField('filtered')
    path = fields.RelatedViewField(
        'path',
        'ryu.services.protocols.bgp.operator.views.bgp.PathDetailView',
    )
    peer = fields.RelatedViewField(
        'received_peer',
        'ryu.services.protocols.bgp.operator.views.bgp.PeerDetailView'
    )

    def encode(self):
        ret = super(ReceivedRouteDetailView, self).encode()
        ret.update({
            'path': self.rel('path').encode(),
        })
        return ret


class DestinationDetailView(OperatorDetailView):
    table = fields.RelatedViewField(
        '_table',
        'ryu.services.protocols.bgp.operator.views.bgp.TableDetailView',
    )
    best_path = fields.RelatedViewField(
        'best_path',
        'ryu.services.protocols.bgp.operator.views.bgp.PathDetailView'
    )
    known_path_list = fields.RelatedListViewField(
        'known_path_list',
        'ryu.services.protocols.bgp.operator.views.bgp.PathListView'
    )
    new_path_list = fields.RelatedListViewField(
        '_new_path_list',
        'ryu.services.protocols.bgp.operator.views.bgp.PathListView'
    )
    withdraw_list = fields.RelatedListViewField(
        '_withdraw_list',
        'ryu.services.protocols.bgp.operator.views.bgp.PathListView'
    )
    sent_routes = fields.RelatedListViewField(
        'sent_routes',
        'ryu.services.protocols.bgp.operator.views.bgp.SentRouteListView'
    )
    nlri = fields.DataField('nlri')
    route_family = fields.DataField('route_family')


class IpNlriDetailView(OperatorDetailView):
    formatted_nlri = fields.DataField('formatted_nlri_str')
    prefix = fields.DataField('prefix')


class VpnNlriDetailView(IpNlriDetailView):
    labels = fields.DataField('label_list')
    rd = fields.DataField('route_dist')


class NlriDetailView(OperatorDetailView):
    def __new__(cls, obj, filter_func=None):
        from ryu.lib.packet.bgp import LabelledVPNIPAddrPrefix
        from ryu.lib.packet.bgp import LabelledVPNIP6AddrPrefix
        from ryu.lib.packet.bgp import IPAddrPrefix, IP6AddrPrefix
        if isinstance(obj, (LabelledVPNIPAddrPrefix,
                            LabelledVPNIP6AddrPrefix)):
            return VpnNlriDetailView(obj)
        elif isinstance(obj, (IPAddrPrefix, IP6AddrPrefix)):
            return IpNlriDetailView(obj)
        else:
            return OperatorDetailView(obj, filter_func)

    def encode(self):
        return self._obj.formatted_nlri_str


class RouteFamilyView(OperatorDetailView):
    afi = fields.DataField('afi')
    safi = fields.DataField('safi')


##################################################################
# Declarations of list and dict views based on detail views above
##################################################################

PeerListView = create_list_view_class(PeerDetailView, 'PeerListView')
PeerDictView = create_dict_view_class(PeerDetailView, 'PeerDictView')

PeerListSummaryView = create_list_view_class(
    PeerDetailSummaryView,
    'PeerListSummaryView'
)

PeerDictSummaryView = create_dict_view_class(
    PeerDetailSummaryView,
    'PeerDictSummaryView'
)

TableDictView = create_dict_view_class(TableDetailView, 'TableDictView')


DestinationListView = create_list_view_class(
    DestinationDetailView, 'DestinationListView'
)

DestinationDictView = create_dict_view_class(
    DestinationDetailView, 'DestinationDictView'
)

PathListView = create_list_view_class(PathDetailView, 'PathListView')
PathDictView = create_dict_view_class(PathDetailView, 'PathDictView')

SentRouteListView = create_list_view_class(
    SentRouteDetailView,
    'SentRouteListView'
)

SentRouteDictView = create_dict_view_class(
    SentRouteDetailView,
    'SentRouteDictView'
)

ReceivedRouteDictView = create_dict_view_class(
    ReceivedRouteDetailView,
    'ReceivedRouteDictView'
)
