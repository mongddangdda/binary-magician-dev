from typing import Tuple, List
from collections import deque
from pathlib import Path
from os import chdir, getcwd

from binaryninja import log_error, log_alert, log_warn, log_info, log_debug
from binaryninja.mediumlevelil import *

from networkx import DiGraph

from bmag.visitor.mlil_ssa import MediumLevelILSsaVisitorMixin


def ssa_var_to_str_key(ssa_var: SSAVariable):
    return f"{ssa_var.name}#{ssa_var.version}"


def get_instr_of_expr(expr: MediumLevelILInstruction) -> MediumLevelILInstruction:
    return expr.function.ssa_form[expr.instr_index]


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

    def visit_unhandled(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:
        
        log_debug(f"unhandled while tracing {src_ssa_var}: {expr.operation}, @0x{expr.address:x}\n{expr_path}")
        return []

    def visit_MLIL_UNARY_OP(
        self, expr: MediumLevelILUnaryBase, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs):

        if src_ssa_var in (expr.src.vars_read + expr.src.vars_written):
            return self.visit(expr.src, src_ssa_var, *args, expr_path=expr_path, **kwargs)
        else:
            return []

    def visit_MLIL_BINARY_OP(
        self, expr: MediumLevelILBinaryBase, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs):

        ret = []
        if src_ssa_var in (expr.left.vars_read + expr.left.vars_written):
            ret += self.visit(expr.left, src_ssa_var, *args, expr_path=expr_path, **kwargs)
        if src_ssa_var in (expr.right.vars_read + expr.right.vars_written):
            ret += self.visit(expr.right, src_ssa_var, *args, expr_path=expr_path, **kwargs)
        return ret

    def visit_MLIL_SET_VAR_SSA(
        self, expr: MediumLevelILSetVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:

        expr_path += (expr.operation, )
        return self.visit(expr.src, src_ssa_var, *args, expr_path=expr_path, **kwargs)

    def visit_MLIL_VAR_SSA(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:

        if not src_ssa_var == expr.src:
            return []

        instr = get_instr_of_expr(expr)

        match expr_path[-1]:
            case MediumLevelILOperation.MLIL_SET_VAR_SSA:
                instr: MediumLevelILSetVarSsa
                self.graph.add_edge(ssa_var_to_str_key(src_ssa_var), ssa_var_to_str_key(instr.dest))
                return [(use_site, instr.dest) for use_site in self.function.get_ssa_var_uses(instr.dest)]
            case _:
                log_warn(f"Invalid expr trace path root: {expr_path[-1]}")
                return []

    def visit_MLIL_ADDRESS_OF(
        self, expr: MediumLevelILAddressOf, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> List[MediumLevelILInstruction]:

        expr_path += (expr.operation, )
        return self.visit(expr.src, src_ssa_var, *args, expr_path=expr_path, **kwargs)
