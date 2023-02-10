from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja import HighLevelILInstruction, MediumLevelILInstruction
    from networkx import DiGraph

from abc import ABC, abstractmethod
from typing import NamedTuple
from .enums import NodeType
from .base import NodeBase


class UnhandledNodeTuple(NamedTuple):
    type: NodeType = NodeType.UNHANDLED
    site: HighLevelILInstruction | MediumLevelILInstruction = None


class UnhandledNode(UnhandledNodeTuple, NodeBase):

    @property
    def label(self):
        return f"{self.type.name}@{self.site.address:x},{self.site.instr_index}"


class UnhandledNodeMixin(ABC):

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    @property
    def unhandled_nodes(self):
        for node in self.nx.nodes():
            if node[0] == NodeType.UNHANDLED:
                yield UnhandledNode(*node)

    def add_unhandled_node(self, site: HighLevelILInstruction | MediumLevelILInstruction):
        node = UnhandledNode(site=site)
        self.nx.add_node(node)

    def get_unhandled_nodes_by_site(self, site: HighLevelILInstruction | MediumLevelILInstruction):
        for unhandled_node in self.unhandled_nodes:
            if unhandled_node.site == site:
                yield unhandled_node

