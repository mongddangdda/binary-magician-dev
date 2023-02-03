from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Dict, Any
    from ..types import AboveMediumIL
    from ..enums import NodeTypes, NodeTypeFlags
    from binaryninja import Variable, SSAVariable
    from networkx import DiGraph


from abc import ABC
from ..enums import NodeTypes, NodeTypeFlags
from ..utils import make_node_id


class BaseNode(ABC):

    @staticmethod
    def create(cls, graph: DiGraph, val: Any, **attr):
        node_id = make_node_id(cls.type, val)
        attr.update(type=cls.type)
        graph.add_node(node_id, **attr)
        return cls(graph, node_id)

    @staticmethod
    def exists(cls, graph: DiGraph, val: Any, **attr):
        node_id = make_node_id(cls.type, val)
        if graph.has_node(node_id):
            return cls(graph, node_id)

    def __init__(self, graph: DiGraph, node_id: str):
        self._graph = graph
        self._node_id = node_id
        assert hasattr(self.__class__, 'type')
        assert type(self.__class__.type) == NodeTypes
        assert self.attr['type'] == self.type

    @property
    def graph(self) -> DiGraph:
        return self._graph

    @property
    def node_id(self) -> Any:
        return self._node_id

    @property
    def attr(self) -> Dict[str, Any]:
        return self.graph.nodes[self.node_id]


class VarNode(BaseNode):

    @staticmethod
    def create(cls: VarNode, graph: DiGraph, var: Variable, **attr):
        attr.update(var=var)
        return BaseNode.create(cls, graph, var, **attr)

    def __init__(self, graph: DiGraph, node_id: str):
        super().__init__(graph, node_id)
        assert self.attr['type'] & NodeTypeFlags.VAR
        assert self.var

    @property
    def var(self):
        return self.attr['var']


class SsaVarNode(BaseNode):

    @staticmethod
    def create(cls: SsaVarNode, graph: DiGraph, ssa_var: SSAVariable, **attr):
        attr.update(ssa_var=ssa_var)
        return BaseNode.create(cls, graph, ssa_var, **attr)

    def __init__(self, graph: DiGraph, node_id: str):
        super().__init__(graph, node_id)
        assert self.attr['type'] & NodeTypeFlags.SSA_VAR
        assert self.ssa_var

    @property
    def ssa_var(self):
        return self.attr['ssa_var']


class SiteNode(BaseNode):

    @staticmethod
    def create(cls: SiteNode, graph: DiGraph, site: AboveMediumIL, **attr):
        attr.update(site=site)
        return BaseNode.create(cls, graph, site, **attr)

    def __init__(self, graph: DiGraph, node_id: str):
        super().__init__(graph, node_id)
        assert self.attr['type'] & NodeTypeFlags.SITE
        assert self.site

    @property
    def site(self):
        return self.attr['site']

