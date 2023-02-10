from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja import HighLevelILInstruction, MediumLevelILInstruction
    from networkx import DiGraph

from abc import ABC, abstractmethod
from typing import NamedTuple
from .enums import NodeType
from .base import NodeBase


class KilledNodeTuple(NamedTuple):
    type: NodeType = NodeType.KILLED
    site: HighLevelILInstruction | MediumLevelILInstruction = None


class KilledNode(KilledNodeTuple, NodeBase):

    @property
    def label(self):
        return f"{self.type.name}@{self.site.address:x},{self.site.instr_index}"


class KilledNodeMixin(ABC):

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    @property
    def killed_nodes(self):
        for node in self.nx.nodes():
            if node[0] == NodeType.KILLED:
                yield KilledNode(*node)

    def add_killed_node(self, site: HighLevelILInstruction | MediumLevelILInstruction):
        node = KilledNode(site=site)
        self.nx.add_node(node)

    def get_killed_nodes_by_site(self, site: HighLevelILInstruction | MediumLevelILInstruction):
        for killed_node in self.killed_nodes:
            if killed_node.site == site:
                yield killed_node

