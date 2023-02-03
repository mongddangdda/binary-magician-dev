from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja import SSAVariable
    from networkx import DiGraph


from abc import ABC, abstractmethod
from .base import SsaVarNode
from ..enums import NodeTypes


class SsaDefNode(SsaVarNode):

    type = NodeTypes.SSA_DEF

    @classmethod
    def create(cls, graph: DiGraph, ssa_var: SSAVariable, **attr):
        return SsaVarNode.create(cls, graph, ssa_var, **attr)

    @classmethod
    def exists(cls, graph: DiGraph, ssa_var: SSAVariable):
        return SsaVarNode.exists(cls, graph, ssa_var)


class GraphSsaDefMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
        ...

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def ssa_defs(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.SSA_DEF):
            yield SsaDefNode(self.graph, node_id)
    
    def add_ssa_def_node(self, ssa_var: SSAVariable, **attr):
        if (exists := self.has_ssa_def_node(ssa_var)):
            return exists
        return SsaDefNode.create(self.graph, ssa_var, **attr)

    def has_ssa_def_node(self, ssa_var: SSAVariable):
        return SsaDefNode.exists(self.graph, ssa_var)

