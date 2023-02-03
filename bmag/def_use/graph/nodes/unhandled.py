from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import AboveMediumIL
    from networkx import DiGraph


from abc import ABC, abstractmethod
from .base import SiteNode
from ..enums import NodeTypes


class UnhandledNode(SiteNode):
    
    type = NodeTypes.UNHANDLED

    @classmethod
    def create(cls, graph: DiGraph, site: AboveMediumIL, **attr):
        return SiteNode.create(cls, graph, site, **attr)

    @classmethod
    def exists(cls, graph: DiGraph, site: AboveMediumIL):
        return SiteNode.exists(cls, graph, site)


class GraphUnhandledMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
        ...

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def unhandled_nodes(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.UNHANDLED):
            yield UnhandledNode(self.graph, node_id)

    def add_unhandled_node(self, site: AboveMediumIL, **attr):
        if (unhandled_node := self.has_unhandled_node(site)):
            return unhandled_node
        return UnhandledNode.create(self.graph, site, **attr)

    def has_unhandled_node(self, site: AboveMediumIL):
        return UnhandledNode.exists(self.graph, site)
