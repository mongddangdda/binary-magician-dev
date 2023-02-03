from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import AboveMediumIL
    from networkx import DiGraph


from abc import ABC, abstractmethod
from .base import SiteNode
from ..enums import NodeTypes


class KilledNode(SiteNode):

    type = NodeTypes.KILLED

    @classmethod
    def create(cls, graph: DiGraph, site: AboveMediumIL, **attr):
        return SiteNode.create(cls, graph, site, **attr)

    @classmethod
    def exists(cls, graph: DiGraph, site: AboveMediumIL):
        return SiteNode.exists(cls, graph, site)


class GraphKilledMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
        ...

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def killed_nodes(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.KILLED):
            yield KilledNode(self.graph, node_id)

    def add_killed_node(self, site: AboveMediumIL, **attr):
        if (killed_node := self.has_killed_node(site)):
            return killed_node
        return KilledNode.create(self.graph, site, **attr)

    def has_killed_node(self, site: AboveMediumIL):
        return KilledNode.exists(self.graph, site)

