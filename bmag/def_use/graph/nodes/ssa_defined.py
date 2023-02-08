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
    def create(cls, graph: DefUseGraph, ssa_var: SSAVariable, **attr):
        return SsaVarNode.create(cls, graph, ssa_var, **attr)

    @classmethod
    def exists(cls, graph: DefUseGraph, ssa_var: SSAVariable):
        return SsaVarNode.exists(cls, graph, ssa_var)


class GraphSsaDefMixin(ABC):

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def ssa_defs(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.SSA_DEF):
            yield SsaDefNode(self, node_id)
    
