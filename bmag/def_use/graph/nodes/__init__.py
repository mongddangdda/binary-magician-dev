from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..enums import NodeTypes
    from networkx import DiGraph


from typing import Dict, TypeVar
from abc import abstractmethod

from .base import BaseNode
from .called import CalledNode, GraphCalledMixin
# from .defined import ...
from .killed import KilledNode, GraphKilledMixin
from .ssa_defined import SsaDefNode, GraphSsaDefMixin
from .unhandled import UnhandledNode, GraphUnhandledMixin


B = TypeVar('B', bound=BaseNode)


class GraphNodesMixin(GraphCalledMixin, GraphKilledMixin, GraphSsaDefMixin, GraphUnhandledMixin):

    nodes: Dict[NodeTypes, B] = {n.type: n for n in [CalledNode, KilledNode, SsaDefNode, UnhandledNode]}

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    def add_node(self, node_type: NodeTypes, *args, **kwargs):
        return self.nodes[node_type].create(self, *args, **kwargs)

    def has_node(self, node_type: NodeTypes, *args):
        return self.nodes[node_type].exists(self, *args)

    def get_node(self, node_type: NodeTypes, *args):
        return self.has_node(node_type, *args)

    def get_node_by_id(self, id: str):
        if not self.nx.has_node(id):
            return
        if 'type' not in self.nx.nodes[id]:
            return
        return self.nodes[self.nx.nodes[id]['type']](self, id)

    def remove_node(self, node_type: NodeTypes, *args):
        if (node := self.has_node(node_type, *args)):
            self.nx.remove_node(node.node_id)

    def remove_node_by_id(self, node_id: str):
        if self.nx.has_node(node_id):
            self.nx.remove_node(node_id)

