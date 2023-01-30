#
#
#


from .killed import KilledNode, GraphKilledMixin
from .no_use import NoUseNode, GraphNoUseMixin

class GraphLeavesMixin(GraphKilledMixin, GraphNoUseMixin):
    pass

