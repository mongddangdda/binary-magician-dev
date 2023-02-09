from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja import SSAVariable
    from ..def_use_graph import DefUseGraph


from abc import ABC, abstractmethod
from .base import SsaVarNode
from ..enums import NodeTypes


class SsaDefNode(SsaVarNode):

    type = NodeTypes.SSA_DEF

    @classmethod
    def make_node_id(cls, ssa_var: SSAVariable):
        return f"{cls.type.name}({ssa_var.name}#{ssa_var.version})"

    @classmethod
    def create(cls, graph: DefUseGraph, ssa_var: SSAVariable, exists_ok=True):
        return super().create(graph, ssa_var, exists_ok)

    @classmethod
    def exists(cls, graph: DefUseGraph, ssa_var: SSAVariable):
        return super().exists(graph, ssa_var)

    @classmethod
    def get(cls, graph: DefUseGraph, ssa_var: SSAVariable):
        return super().get(graph, ssa_var)


class GraphSsaDefMixin(ABC):

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def ssa_defs(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.SSA_DEF):
            yield SsaDefNode(self, node_id)
    
