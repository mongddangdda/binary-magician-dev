from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja import SSAVariable
    from networkx import DiGraph

from abc import ABC, abstractmethod
from typing import NamedTuple
from .enums import NodeType
from .base import NodeBase


class SsaVarDefNodeTuple(NamedTuple):
    type: NodeType = NodeType.SSA_VAR_DEF
    ssa_var: SSAVariable = None


class SsaVarDefNode(SsaVarDefNodeTuple, NodeBase):

    @property
    def label(self):
        return f"{self.type.name}({self.ssa_var.name}#{self.ssa_var.version})"


class SsaVarDefNodeMixin(ABC):

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    @property
    def ssa_var_def_nodes(self):
        for node in self.nx.nodes():
            if node[0] == NodeType.SSA_VAR_DEF:
                yield SsaVarDefNode(*node)

    def add_ssa_var_def_node(self, ssa_var: SSAVariable):
        node = SsaVarDefNode(ssa_var=ssa_var)
        self.nx.add_node(node)

    def get_ssa_var_def_nodes_by_site(self, ssa_var: SSAVariable):
        for ssa_var_def_node in self.ssa_var_def_nodes:
            if ssa_var_def_node.ssa_var == ssa_var:
                yield ssa_var_def_node

