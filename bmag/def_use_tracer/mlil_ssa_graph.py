from binaryninja import BinaryView, SSAVariable
from binaryninja.mediumlevelil import *
from networkx import MultiDiGraph, DiGraph
from pathlib import Path
from typing import Any, List


def ssa_var_to_str(ssa_var: SSAVariable):
    return f"{ssa_var.name}#{ssa_var.version}"


class DefUseMediumLevelILSsaGraph:
    
    def __init__(self):
        self.graph = DiGraph()

    def add_def(self, ssa_var: SSAVariable) -> str | None:
        ssa_var_str = ssa_var_to_str(ssa_var)
        self.graph.add_node(ssa_var_str, type='def', ssa_var=ssa_var)
        return ssa_var_str

    def add_use(self, src_ssa_var: SSAVariable, dst_ssa_var: SSAVariable):
        use_site = dst_ssa_var.function.mlil.ssa_form.get_ssa_var_definition(dst_ssa_var)
        src_ssa_var_str = self.add_def(src_ssa_var)
        dst_ssa_var_str = self.add_def(dst_ssa_var)
        self.graph.add_edge(src_ssa_var_str, dst_ssa_var_str, type='use', instr=use_site)

    def add_end(self, src_ssa_var: SSAVariable, *args):
        src_ssa_var_str = self.add_def(src_ssa_var)
        if len(args) == 1:
            dst_instr: MediumLevelILInstruction = args[0]
            dst_str = f"KILLED({src_ssa_var_str})"
            self.graph.add_node(dst_str, type='end', subtype='killed', ssa_var=src_ssa_var, instr=dst_instr)
            self.graph.add_edge(src_ssa_var_str, dst_str, type='use', instr=dst_instr)
            return dst_str
        else:
            self.graph.nodes[src_ssa_var_str]['type'] = 'end'
            self.graph.nodes[src_ssa_var_str]['subtype'] = 'no_use'
            return src_ssa_var_str

    def has_use_of(self, src_node: SSAVariable, dst_node: SSAVariable):

        src_node_key = ssa_var_to_str(src_node)
        dst_node_key = ssa_var_to_str(dst_node)

        if not self.graph.has_node(src_node_key):
            return False
        
        if not self.graph.has_node(dst_node_key):
            return False

        if not self.graph.has_edge(src_node_key, dst_node_key):
            return False

        return True

    def ssa_vars(self):
        for node, attr in self.graph.nodes(data=True):
            if not attr:
                continue
            if 'type' not in attr or 'ssa_var' not in attr:
                continue
            if attr['type'] != 'def':
                continue
            yield attr['ssa_var']

    def end_points(self):
        for node, attr in self.graph.nodes(data=True):
            if not attr:
                continue
            if 'type' not in attr:
                continue
            if attr['type'] != 'end':
                continue
            yield attr

    def killed_points(self):
        for attr in self.end_points():
            if 'subtype' not in attr:
                continue
            if attr['subtype'] != 'killed':
                continue
            yield attr

    def no_use_points(self):
        for attr in self.end_points():
            if 'subtype' not in attr:
                continue
            if attr['subtype'] != 'no_use':
                continue
            yield attr

    def save_html_to(self, filepath: str | Path):

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

