from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from networkx import DiGraph
    from .base import NodeBaseType as N

from abc import abstractmethod
from .called import CalledNodeMixin, CalledNode
from .killed import KilledNodeMixin, KilledNode
from .unhandled import UnhandledNodeMixin, UnhandledNode
from .ssa_var_def import SsaVarDefNodeMixin, SsaVarDefNode


class NodeMixin(CalledNodeMixin, KilledNodeMixin, UnhandledNodeMixin, SsaVarDefNodeMixin):

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...   

    def add_node(self, node: N):
        self.nx.add_node(node)

    def has_node(self, node: N):
        return self.nx.has_node(node)

    def remove_node(self, node: N):
        self.nx.remove_node(node)

    def replace_node(self, target: N, replace: N):

        if not self.has_node(target):
            raise ValueError
        if not self.has_node(replace):
            raise ValueError
        
        src_nodes = [n for n, _ in self.nx.in_edges(target)]
        dst_nodes = [n for _, n in self.nx.out_edges(target)]

        self.remove_node(target)

        for n in src_nodes:
            self.nx.add_edge(n, replace)

        for n in dst_nodes:
            self.nx.add_edge(replace, n)

