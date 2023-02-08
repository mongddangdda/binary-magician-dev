from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Dict, Any
    from ..def_use_graph import DefUseGraph
    from ..types import AboveMediumIL
    from binaryninja import Variable, SSAVariable


from abc import ABC
from ..utils import make_node_id


class BaseNode(ABC):

    @staticmethod
    def create(cls, graph: DefUseGraph, val: Any, **attr):
        node_id = make_node_id(cls.type, val)
        attr.update(type=cls.type)
        graph.nx.add_node(node_id, **attr)
        return cls(graph, node_id)

    @staticmethod
    def exists(cls, graph: DefUseGraph, val: Any):
        node_id = make_node_id(cls.type, val)
        if graph.nx.has_node(node_id):
            return cls(graph, node_id)

    def __init__(self, graph: DefUseGraph, node_id: str):
        self._graph = graph
        self._node_id = node_id

    @property
    def graph(self) -> DefUseGraph:
        return self._graph

    @property
    def node_id(self) -> Any:
        return self._node_id

    @property
    def attr(self) -> Dict[str, Any]:
        return self.graph.nx.nodes[self.node_id]


class VarNode(BaseNode):

    @staticmethod
    def create(cls: VarNode, graph: DefUseGraph, var: Variable, **attr):
        attr.update(var=var)
        return BaseNode.create(cls, graph, var, **attr)

    def __init__(self, graph: DefUseGraph, node_id: str):
        super().__init__(graph, node_id)

    @property
    def var(self):
        return self.attr['var']


class SsaVarNode(BaseNode):

    @staticmethod
    def create(cls: SsaVarNode, graph: DefUseGraph, ssa_var: SSAVariable, **attr):
        attr.update(ssa_var=ssa_var)
        return BaseNode.create(cls, graph, ssa_var, **attr)

    def __init__(self, graph: DefUseGraph, node_id: str):
        super().__init__(graph, node_id)

    @property
    def ssa_var(self):
        return self.attr['ssa_var']


class SiteNode(BaseNode):

    @staticmethod
    def create(cls: SiteNode, graph: DefUseGraph, site: AboveMediumIL, **attr):
        attr.update(site=site)
        return BaseNode.create(cls, graph, site, **attr)

    def __init__(self, graph: DefUseGraph, node_id: str):
        super().__init__(graph, node_id)

    @property
    def site(self):
        return self.attr['site']

