from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import AboveMediumIL
    from ..def_use_graph import DefUseGraph


from abc import ABC, abstractmethod
from .base import SiteNode
from ..enums import NodeTypes


class CalledNode(SiteNode):
    
    type = NodeTypes.CALLED

    @classmethod
    def create(cls, graph: DefUseGraph, site: AboveMediumIL, **attr):
        return SiteNode.create(cls, graph, site, **attr)

    @classmethod
    def exists(cls, graph: DefUseGraph, site: AboveMediumIL):
        return SiteNode.exists(cls, graph, site)


class GraphCalledMixin(ABC):

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def called_nodes(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.CALLED):
            yield CalledNode(self, node_id)

