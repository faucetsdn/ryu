from ryu.services.protocols.bgp.operator.views.base import \
    create_dict_view_class
from ryu.services.protocols.bgp.operator.views.base import OperatorDetailView
from ryu.services.protocols.bgp.operator.views import fields


class ConfDetailView(OperatorDetailView):
    settings = fields.DataField('_settings')

    def encode(self):
        return self.get_field('settings')


ConfDictView = create_dict_view_class(ConfDetailView, 'ConfDictView')
