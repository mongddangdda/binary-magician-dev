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

    node_classes: Dict[NodeTypes, B] = {n.type: n for n in [CalledNode, KilledNode, SsaDefNode, UnhandledNode]}

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    def add_node(self, node_type: NodeTypes, *args, **kwargs):
        return self.node_classes[node_type].create(self, *args, **kwargs)

    def has_node(self, node_type: NodeTypes, *args):
        return self.node_classes[node_type].exists(self, *args)

    def has_node_with_id(self, node_id: str):
        return self.nx.has_node(node_id)

    def get_node(self, node_type: NodeTypes, *args):
        return self.node_classes[node_type](self, *args)

    def get_node_by_id(self, id: str):
        if not self.has_node_with_id(id):
            return
        return self.node_classes[self.nx.nodes[id]['type']](self, id)

    def remove_node(self, node_type: NodeTypes, *args):
        if (node := self.has_node(node_type, *args)):
            self.nx.remove_node(node.node_id)

    def remove_node_by_id(self, node_id: str):
        if self.nx.has_node(node_id):
            self.nx.remove_node(node_id)

    def replace_node(self, orig_node: B, node_type: NodeTypes, *args, **kwargs):
        
        src_node_ids = [n for n, _ in orig_node.in_edges]
        dst_node_ids = [n for _, n in orig_node.out_edges]
        
        new_node = self.add_node(node_type, *args, **kwargs)
        
        self.remove_node_by_id(orig_node.node_id)

        for src_node_id in src_node_ids:
            self.nx.add_edge(src_node_id, new_node.node_id)

        for dst_node_id in dst_node_ids:
            self.nx.add_edge(new_node.node_id, dst_node_id)

    def replace_node_by_id(self, orig_node_id: str, node_type: NodeTypes, *args, **kwargs):
        orig_node = self.get_node_by_id(orig_node_id)
        return self.replace_node(orig_node, node_type, *args, **kwargs)

