from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .types import AboveMediumIL
    from binaryninja import SSAVariable

from networkx import DiGraph

from .utils import GraphUtilsMixin
from .nodes import GraphNodesMixin
from .enums import NodeTypes, NodeTypeFlags
from .nodes import BaseNode


class DefUseGraph(GraphUtilsMixin, GraphNodesMixin):

    def __init__(self):
        self._nx = DiGraph()

    @property
    def nx(self):
        return self._nx

    def iter_nodes_with_type(self, node_type: NodeTypes):
        for node_id, attr in self.nx.nodes(data=True):
            if 'type' not in attr:
                continue
            if attr['type'] != node_type:
                continue
            yield (node_id, attr)

    def iter_nodes_with_flags(self, node_flags: NodeTypeFlags):
        for node_id, attr in self.nx.nodes(data=True):
            if 'type' not in attr:
                continue
            if not (attr['type'] & node_flags):
                continue
            yield (node_id, attr)

    def add_edge(self, src: BaseNode, dst: BaseNode, **attr):
        self.nx.add_edge(src.node_id, dst.node_id, **attr)
        return (src.node_id, dst.node_id)

    def has_edge(self, *args, **kwargs):
        raise NotImplementedError

