from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Dict, Any
    from binaryninja import Variable, SSAVariable
    from bmag.def_use.graph.def_use_graph import DefUseGraph
    from bmag.def_use.graph.types import AboveMediumIL
    from bmag.def_use.graph.enums import NodeTypes


from abc import ABC, abstractmethod


class BaseNode(ABC):

    type: NodeTypes = None

    @classmethod
    def make_node_id(cls, val: Any) -> str:
        assert cls.type
        return str(val)

    @classmethod
    def create(cls, graph: DefUseGraph, val: Any, exists_ok=True, attr: Dict = {}):

        assert cls.type

        node_id = cls.make_node_id(val)
        if graph.nx.has_node(node_id):
            if not exists_ok:
                raise ValueError(f"node '{node_id}' already exists.")
            return cls(graph, node_id)

        attr.update(type=cls.type)
        graph.nx.add_node(node_id, **attr)
        return cls(graph, node_id)

    @classmethod
    def exists(cls, graph: DefUseGraph, val: Any):
        assert cls.type
        node_id = cls.make_node_id(val)
        return cls.check_exists_by_node_id(node_id)

    @classmethod
    def check_exists_by_node_id(cls, graph: DefUseGraph, node_id: str):
        return graph.nx.has_node(node_id)

    @classmethod
    def get(cls, graph: DefUseGraph, val: Any):
        assert cls.type
        node_id = cls.make_node_id(val)
        return cls.get_by_node_id(graph, node_id)

    @classmethod
    def get_by_node_id(cls, graph: DefUseGraph, node_id: str):
        if not cls.check_exists_by_node_id(graph, node_id):
            raise ValueError(f"node '{node_id}' not exists.")
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

    @property
    def in_edges(self):
        return self.graph.nx.in_edges(self.node_id)

    @property
    def out_edges(self):
        return self.graph.nx.out_edges(self.node_id)


class VarNode(BaseNode):

    type: NodeTypes = None

    @classmethod
    def make_node_id(cls, var: Variable):
        return f"VAR({var.name})"

    @classmethod
    def create(cls, graph: DefUseGraph, var: Variable, exists_ok=True, attr: Dict = {}):
        attr.update(var=var)
        return super().create(graph, var, exists_ok, attr)

    @classmethod
    def exists(cls, graph: DefUseGraph, var: Variable):
        return super().get(graph, var)

    @classmethod
    def get(cls, graph: DefUseGraph, var: Variable):
        return super().get(graph, var)

    def __init__(self, graph: DefUseGraph, node_id: str):
        super().__init__(graph, node_id)

    @property
    def var(self):
        return self.attr['var']


class SsaVarNode(BaseNode):

    type: NodeTypes = None

    @classmethod
    def make_node_id(cls, ssa_var: SSAVariable):
        return f"SSA_VAR({ssa_var.name}#{ssa_var.version})"

    @classmethod
    def create(cls, graph: DefUseGraph, ssa_var: SSAVariable, exists_ok=True, attr: Dict = {}):
        attr.update(ssa_var=ssa_var)
        return super().create(graph, ssa_var, exists_ok, attr)

    @classmethod
    def exists(cls, graph: DefUseGraph, ssa_var: SSAVariable):
        return super().exists(graph, ssa_var)

    @classmethod
    def get(cls, graph: DefUseGraph, ssa_var: SSAVariable):
        return super().get(graph, ssa_var)

    def __init__(self, graph: DefUseGraph, node_id: str):
        super().__init__(graph, node_id)

    @property
    def ssa_var(self):
        return self.attr['ssa_var']


class SiteNode(BaseNode):

    type: NodeTypes = None

    @classmethod
    def make_node_id(cls, val: Any) -> str:
        return super().make_node_id(val)

    @classmethod
    def create(cls, graph: DefUseGraph, site: AboveMediumIL, exists_ok=True, attr: Dict = {}):
        attr.update(site=site)
        return super().create(graph, site, exists_ok, attr)

    @classmethod
    def exists(cls, graph: DefUseGraph, site: AboveMediumIL):
        return super().exists(graph, site)

    @classmethod
    def get(cls, graph: DefUseGraph, site: AboveMediumIL):
        return super().get(graph, site)

    def __init__(self, graph: DefUseGraph, node_id: str):
        super().__init__(graph, node_id)

    @property
    def site(self):
        return self.attr['site']

