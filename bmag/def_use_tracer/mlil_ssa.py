from typing import Tuple, List
from collections import deque
from pathlib import Path
from os import chdir, getcwd

from binaryninja import log_error, log_alert, log_warn, log_info, log_debug
from binaryninja.mediumlevelil import *

from networkx import DiGraph

from ..visitor.mlil_ssa import MediumLevelILSsaVisitorMixin


def ssa_var_to_str_key(ssa_var: SSAVariable):
    return f"{ssa_var.name}#{ssa_var.version}"

class DefUseMediumLevelSsaTracer(MediumLevelILSsaVisitorMixin):

    handlers = {}

    def __init__(self, ssa_var: SSAVariable):
        self.start: SSAVariable = ssa_var
        self.function: MediumLevelILFunction = ssa_var.function.mlil.ssa_form
        self.to_visit: deque[Tuple[MediumLevelILInstruction, SSAVariable]] = deque()
        self.graph: DiGraph = None
        self.trace()

    def save_graph_to_image(self, filepath: str | Path):

        from pyvis.network import Network

        if type(filepath) == str:
            filepath = Path(filepath)

        pwd = getcwd()

        try:
            net = Network(directed=True)
            net.from_nx(self.graph)
            chdir(filepath.parent)
            net.show(filepath.name, local=False)
        
        finally:
            chdir(pwd)

    def trace(self):

        # make graph for result.
        self.graph = DiGraph()
        self.graph.add_node(ssa_var_to_str_key(self.start))

        # initial visit sites.
        self.to_visit.extend(
            [(use_site, self.start) for use_site in self.function.get_ssa_var_uses(self.start)]
        )

        # traverse!
        while self.to_visit:
            next_site, src_ssa_var = self.to_visit.pop()
            next_sites = self.visit(next_site, src_ssa_var)
            self.to_visit.extend(next_sites)

    def visit(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:

        return MediumLevelILSsaVisitorMixin.visit(self, expr, src_ssa_var, *args, expr_path=expr_path, **kwargs)

    def visit_Generic(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:
        
        log_debug(f"unhandled while tracing {src_ssa_var}: {expr.operation}, @0x{expr.address:x}\n{expr_path}")
        return []

    def visit_MLIL_SET_VAR_SSA(
        self, expr: MediumLevelILSetVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:

        expr_path += (expr.operation, )

        # tell tracer to next visit place.
        next_sites = []
        next_sites += [(use_site, expr.dest) for use_site in self.function.get_ssa_var_uses(expr.dest)]
        next_sites += self.visit(expr.src, src_ssa_var, expr_path=expr_path)

        # update graph.
        self.graph.add_edge(ssa_var_to_str_key(src_ssa_var), ssa_var_to_str_key(expr.dest))

        return next_sites

    def visit_MLIL_VAR_SSA(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:

        match expr_path[-1]:
            case MediumLevelILOperation.MLIL_SET_VAR_SSA:
                if src_ssa_var != expr.src:
                    log_warn(f"{expr.src} != {src_ssa_var} @ 0x{expr.address:x}")
            case _:
                log_warn(f"Invalid expr trace path root: {expr_path[-1]}")

        return []

