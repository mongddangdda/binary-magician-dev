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
        self._graph = DiGraph()

    @property
    def graph(self):
        return self._graph

    def iter_nodes_with_type(self, node_type: NodeTypes):
        for node_id, attr in self.graph.nodes(data=True):
            if 'type' not in attr:
                continue
            if attr['type'] != node_type:
                continue
            yield (node_id, attr)

    def iter_nodes_with_flags(self, node_flags: NodeTypeFlags):
        for node_id, attr in self.graph.nodes(data=True):
            if 'type' not in attr:
                continue
            if not (attr['type'] & node_flags):
                continue
            yield (node_id, attr)

    def add_node(self, node_type: NodeTypes, *args, **attr):
        match node_type:
            case NodeTypes.CALLED:
                return self.add_called_node(*args, **attr)
            case NodeTypes.DEF:
                raise NotImplementedError
            case NodeTypes.KILLED:
                return self.add_killed_node(*args, **attr)
            case NodeTypes.SSA_DEF:
                return self.add_ssa_def_node(*args, **attr)
            case NodeTypes.UNHANDLED:
                return self.add_unhandled_node(*args, **attr)
            case _:
                raise ValueError

    def has_node(self, node_type: NodeTypes, *args):
        match node_type:
            case NodeTypes.CALLED:
                return self.has_called_node(*args)
            case NodeTypes.DEF:
                raise NotImplementedError
            case NodeTypes.KILLED:
                return self.has_killed_node(*args)
            case NodeTypes.SSA_DEF:
                return self.has_ssa_def_node(*args)
            case NodeTypes.UNHANDLED:
                return self.has_unhandled_node(*args)
            case _:
                raise ValueError

    def chain(self, src: BaseNode, dst: BaseNode, **attr):
        self.graph.add_edge(src.node_id, dst.node_id, **attr)
        return (src.node_id, dst.node_id)

