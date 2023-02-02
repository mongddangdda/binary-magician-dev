from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .types import *
    from typing import Tuple


from networkx import DiGraph

from .base import BaseNode, BaseEdge
from .utils import GraphUtilsMixin, ssa_var_to_str
from .leaves import GraphLeavesMixin
from .enums import NodeTypes, EdgeTypes


class DefNode(BaseNode):

    def __init__(self, graph: DiGraph, node_id: str):
        super().__init__(graph, node_id)
        assert self.ssa_var

    @classmethod
    def create(cls, graph: DiGraph, def_ssa_var: SSAVariable, **attr):
        node_id = ssa_var_to_str(def_ssa_var)
        attr.update(type = NodeTypes.DEF,
                    ssa_var = def_ssa_var)
        graph.add_node(node_id, **attr)
        return cls(graph, node_id)

    @property
    def type(self) -> NodeTypes:
        return NodeTypes.DEF

    @property
    def ssa_var(self) -> SSAVariable:
        return self.attr['ssa_var']


class UseEdge(BaseEdge):

    def __init__(self, graph: DiGraph, edge_id: Tuple[str, str]):
        super().__init__(graph, edge_id)

    @classmethod
    def create(cls, graph: DiGraph, src_ssa_var: SSAVariable, dst_ssa_var: SSAVariable, **attr):

        if not graph.has_node(src_ssa_var_str := ssa_var_to_str(src_ssa_var)):
            src_node = DefNode.create(graph, src_ssa_var)
            assert src_node.node_id == src_ssa_var_str

        if not graph.has_node(dst_ssa_var_str := ssa_var_to_str(dst_ssa_var)):
            dst_node = DefNode.create(graph, dst_ssa_var)
            assert dst_node.node_id == dst_ssa_var_str

        attr.update(type = EdgeTypes.USE)

        graph.add_edge(src_ssa_var_str, dst_ssa_var_str, **attr)

        return cls(graph, (src_ssa_var_str, dst_ssa_var_str))

    @property
    def type(self) -> NodeTypes:
        return EdgeTypes.USE


class DefUseGraph(GraphUtilsMixin, GraphLeavesMixin):

    def __init__(self):
        self._graph = DiGraph()

    @property
    def graph(self):
        return self._graph

    @property
    def defs(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.DEF):
            yield DefNode(self.graph, node_id)

    @property
    def uses(self):
        for edge_id, attr in self.iter_edges_with_type(EdgeTypes.USE):
            yield UseEdge(self.graph, *edge_id)

    def add_def(self, ssa_var: SSAVariable, **attr):
        return DefNode.create(self.graph, ssa_var, **attr)

    def add_use(self, src_ssa_var: SSAVariable, dst_ssa_var: SSAVariable, **attr):
        return UseEdge.create(self.graph, src_ssa_var, dst_ssa_var, **attr)

    def iter_nodes_with_type(self, node_type: NodeTypes):
        for node_id, attr in self.graph.nodes(data=True):
            if 'type' not in attr:
                continue
            if attr['type'] != node_type:
                continue
            yield (node_id, attr)

    def iter_edges_with_type(self, edge_type: EdgeTypes):
        for edge_id, attr in self.graph.edges(data=True):
            if 'type' not in attr:
                continue
            if attr['type'] != edge_type:
                continue
            yield (edge_id, attr)

