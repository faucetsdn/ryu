from ryu.services.protocols.bgp.operator.views.base import \
    create_dict_view_class
from ryu.services.protocols.bgp.operator.views.base import OperatorDetailView
from ryu.services.protocols.bgp.operator.views import fields


class ImportmapManagerDetailView(OperatorDetailView):
    importmaps = fields.RelatedDictViewField(
        '_import_maps_by_name',
        'ryu.services.protocols.bgp.operator.views.other.ImportmapDictView'
    )


class ImportmapDetailView(OperatorDetailView):
    nlri = fields.OptionalDataField('_nlri')
    rt = fields.OptionalDataField('_rt')

    def encode(self):
        ret = {}
        nlri = self.get_field('nlri')
        if nlri is not None:
            ret.update({'nlri': nlri})

        rt = self.get_field('rt')
        if rt is not None:
            ret.update({'rt': rt})

        return ret


ImportmapDictView = create_dict_view_class(
    ImportmapDetailView,
    'ImportmapDictView'
)
