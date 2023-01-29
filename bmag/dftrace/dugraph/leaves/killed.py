#
# File header here
#


from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import *
    from typing import Any, List, Tuple


from abc import ABC, abstractmethod

from ..utils import ssa_var_to_str
from ..enums import NodeTypes, EdgeTypes
from ..base import BaseNode, BaseEdge


def ssa_var_to_killed_node_id(ssa_var: SSAVariable):
    return f"KILLED({ssa_var_to_str(ssa_var)})"


class KilledNode(BaseNode):
    
    def __init__(self, graph: DiGraph, node_id: str):
        super().__init__(graph, node_id)
        assert self.ssa_var
        assert self.site

    @classmethod
    def create(cls, graph: DiGraph, src_ssa_var: SSAVariable, site: AboveMediumIL, **attr):
        node_id = ssa_var_to_killed_node_id(src_ssa_var)
        attr.update(type = NodeTypes.KILLED,
                    src_ssa_var = src_ssa_var,
                    site = site)
        graph.add_node(node_id, **attr)
        return cls(graph, node_id)

    @property
    def type(self) -> NodeTypes:
        return NodeTypes.KILLED

    @property
    def ssa_var(self) -> NodeTypes:
        return self.attr['src_ssa_var']

    @property
    def site(self) -> Any | List[Any]:
        return self.attr['site']


class KilledEdge(BaseEdge):

    @classmethod
    def create(cls, graph: DiGraph, src_ssa_var: SSAVariable, site: AboveMediumIL, **attr):
        
        if not graph.has_node(src_ssa_var_str := ssa_var_to_str(src_ssa_var)):
            raise Exception # TODO: handle this case !

        if not graph.has_node(dst_str := ssa_var_to_killed_node_id(src_ssa_var)):
            killed_node = KilledNode.create(graph, src_ssa_var, site, **attr)
            assert dst_str == killed_node.node_id

        attr.update(type = EdgeTypes.USE)

        graph.add_edge(src_ssa_var_str, dst_str, **attr)

        return KilledEdge(graph, (src_ssa_var_str, dst_str))

    @property
    def type(self) -> EdgeTypes:
        return EdgeTypes.USE


class GraphKilledMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
        ...

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def ends_with_killed(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.KILLED):
            yield KilledNode(self.graph, node_id)

    def add_end_with_killed(self, src_ssa_var: SSAVariable, site: AboveMediumIL, link=False, **attr):
        killed_edge = KilledEdge.create(self.graph, src_ssa_var, site, **attr)
        _, dst = killed_edge.edge_id
        return KilledNode(self.graph, dst)

