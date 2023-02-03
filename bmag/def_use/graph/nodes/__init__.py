from .base import BaseNode
from .called import CalledNode, GraphCalledMixin
# from .defined import ...
from .killed import KilledNode, GraphKilledMixin
from .ssa_defined import SsaDefNode, GraphSsaDefMixin
from .unhandled import UnhandledNode, GraphUnhandledMixin

class GraphNodesMixin(GraphCalledMixin, GraphKilledMixin, GraphSsaDefMixin, GraphUnhandledMixin):
    pass

