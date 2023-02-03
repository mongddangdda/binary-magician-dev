from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import AboveMediumIL
    from typing import Any
    from networkx import DiGraph


from abc import ABC, abstractmethod
from .base import SiteNode
from ..enums import NodeTypes


class CalledNode(SiteNode):
    
    type = NodeTypes.CALLED

    @classmethod
    def create(cls, graph: DiGraph, site: AboveMediumIL, **attr):
        return SiteNode.create(cls, graph, site, **attr)

    @classmethod
    def exists(cls, graph: DiGraph, val: Any):
        return SiteNode.exists(cls, graph, val)


class GraphCalledMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
        ...

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def called_nodes(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.CALLED):
            yield CalledNode(self.graph, node_id)

    def add_called_node(self, site: AboveMediumIL, **attr):
        if (called_node := self.has_called_node(site)):
            return called_node
        return CalledNode.create(self.graph, site, **attr)

    def has_called_node(self, site: AboveMediumIL):
        return CalledNode.exists(self.graph, site)

