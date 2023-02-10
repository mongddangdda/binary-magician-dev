from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from nodes.base import NodeBaseType as N

from networkx import DiGraph
from .nodes import NodeMixin
from .graph_util_mixin import GraphUtilMixin


class Graph(NodeMixin, GraphUtilMixin):

    def __init__(self):
        self._nx = DiGraph()

    @property
    def nx(self):
        return self._nx

    def add_edge(self, u_of_edge: N, v_of_edge: N):
        self.nx.add_edge(u_of_edge, v_of_edge)

    def has_edge(self, u: N, v: N):
        return self.nx.has_edge(u, v)

    def remove_edge(self, u: N, v: N):
        return self.nx.remove_edge(u, v)