#
#
#


from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .types import *


from networkx import DiGraph
from abc import ABC, abstractmethod
from pathlib import Path


class GraphUtilsMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> 'DiGraph':
        ...

    def export_html(self, filepath: str | Path) -> None:

        from pyvis.network import Network
        from os import getcwd, chdir

        if type(filepath) == str:
            filepath = Path(filepath)

        pwd = getcwd()

        graph = DiGraph()
        graph.add_nodes_from(self.graph.nodes(data=False))
        graph.add_edges_from(self.graph.edges(data=False))

        try:
            net = Network(directed=True)
            net.from_nx(graph)
            chdir(filepath.parent)
            net.show(filepath.name, local=False)
        
        finally:
            chdir(pwd)


def ssa_var_to_str(ssa_var: 'SSAVariable'):
    return f"{ssa_var.name}#{ssa_var.version}"

