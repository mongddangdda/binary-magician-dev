from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Any
    from .types import AboveMediumIL
    from binaryninja import SSAVariable


from abc import ABC, abstractmethod
from pathlib import Path
from networkx import DiGraph

from .enums import NodeTypes, NodeTypeFlags


class GraphUtilsMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
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


def ssa_var_to_str(ssa_var: SSAVariable):
    return f"{ssa_var.name}#{ssa_var.version}"


def ssa_var_to_node_id(node_type: NodeTypes, ssa_var: SSAVariable):
    return f"{node_type.name}({ssa_var_to_str(ssa_var)})"


def site_to_node_id(node_type: NodeTypes, site: AboveMediumIL):
    return f"{node_type.name} @ 0x{site.address:x}"


def make_node_id(node_type: NodeTypes, val: Any):
    if node_type & NodeTypeFlags.VAR:
        raise NotImplementedError
    elif node_type & NodeTypeFlags.SSA_VAR:
        return ssa_var_to_node_id(node_type, val)
    elif node_type & NodeTypeFlags.SITE:
        return site_to_node_id(node_type, val)
    else:
        raise Exception(f"node_type = {node_type.name}")

