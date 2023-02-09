from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import AboveMediumIL
    from ..def_use_graph import DefUseGraph


from abc import ABC, abstractmethod
from .base import SiteNode
from ..enums import NodeTypes


class UnhandledNode(SiteNode):
    
    type = NodeTypes.UNHANDLED

    @classmethod
    def create(cls, graph: DefUseGraph, site: AboveMediumIL, exists_ok=True):
        return SiteNode.create(cls, graph, site, exists_ok)

    @classmethod
    def exists(cls, graph: DefUseGraph, site: AboveMediumIL):
        return SiteNode.exists(cls, graph, site)


class GraphUnhandledMixin(ABC):

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def unhandled_nodes(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.UNHANDLED):
            yield UnhandledNode(self, node_id)

