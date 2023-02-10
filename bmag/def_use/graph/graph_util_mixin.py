from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    pass

from abc import ABC, abstractmethod
from pathlib import Path
from networkx import DiGraph


class GraphUtilMixin(ABC):

    @property
    @abstractmethod
    def nx(self) -> DiGraph:
        ...

    def export_html(self, filepath: str | Path) -> None:

        from pyvis.network import Network
        from os import getcwd, chdir

        if type(filepath) == str:
            filepath = Path(filepath)

        pwd = getcwd()

        graph = DiGraph()
        graph.add_nodes_from([n.label for n in self.nx.nodes(data=False)])
        graph.add_edges_from([(u.label, v.label) for u, v in self.nx.edges(data=False)])

        try:
            net = Network(directed=True)
            net.from_nx(graph)
            chdir(filepath.parent)
            net.show(filepath.name, local=False)
        
        finally:
            chdir(pwd)