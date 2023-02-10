from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja import HighLevelILInstruction, MediumLevelILInstruction
    from networkx import DiGraph

from abc import ABC, abstractmethod
from typing import NamedTuple
from .enums import NodeType
from .base import NodeBase


class CalledNodeTuple(NamedTuple):
    type: NodeType = NodeType.CALLED
    site: HighLevelILInstruction | MediumLevelILInstruction = None


class CalledNode(CalledNodeTuple, NodeBase):

    @property
    def label(self):
        return f"{self.type.name}@{self.site.address:x},{self.site.instr_index}"


class CalledNodeMixin(ABC):

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    @property
    def called_nodes(self):
        for node in self.nx.nodes():
            if node[0] == NodeType.CALLED:
                yield CalledNode(*node)

    def add_called_node(self, site: HighLevelILInstruction | MediumLevelILInstruction):
        node = CalledNode(site=site)
        self.nx.add_node(node)

    def get_called_nodes_by_site(self, site: HighLevelILInstruction | MediumLevelILInstruction):
        for called_node in self.called_nodes:
            if called_node.site == site:
                yield called_node

