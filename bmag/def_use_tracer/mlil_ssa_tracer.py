from typing import Tuple
from collections import deque

from binaryninja import log_error, log_alert, log_warn, log_info, log_debug
from binaryninja.mediumlevelil import *

from bmag.visitor.mlil import MediumLevelILSsaVisitor

from .result import Visited, VisitedResult, VisitedResultFlag
from .mlil_ssa_graph import DefUseMediumLevelILSsaGraph


class DefUseMediumLevelSsaTracer(MediumLevelILSsaVisitor):

    def __init__(self, ssa_var: SSAVariable):
        self.start: SSAVariable = ssa_var
        self.to_visit: deque[Tuple[MediumLevelILInstruction, SSAVariable]] = deque()
        self.visited: list[MediumLevelILInstruction] = list()
        self.graph: DefUseMediumLevelILSsaGraph = None
        self.trace()

    def trace(self):

        # make graph for result.
        self.graph = DefUseMediumLevelILSsaGraph()
        self.graph.add_def(self.start)

        # initial visit sites.
        self.to_visit.extend(
            [(use_site, self.start) for use_site in self.start.function.mlil.ssa_form.get_ssa_var_uses(self.start)]
        )

        # traverse!
        while self.to_visit:
            
            curr_site, src_ssa_var = self.to_visit.pop()
            
            visited = self.visit(curr_site, src_ssa_var)

            match visited.result:
                case VisitedResult.VISITED:
                    for site, ssa_var in visited.next_sites():
                        self.graph.add_use(src_ssa_var, ssa_var)
                        self.to_visit.append((site, ssa_var))
                case VisitedResult.NO_USE:
                    for definition in visited.def_and_uses:
                        self.graph.add_end(definition)
                case VisitedResult.KILLED:
                    self.graph.add_end(src_ssa_var, curr_site)
                case VisitedResult.INVALID:
                    self.graph.add_end(src_ssa_var, curr_site)

            self.visited.append(curr_site)

    #
    # Base
    #

    def visit(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> Visited:

        visited = self.visit_MLIL_SSA(expr, src_ssa_var, *args, expr_path=expr_path, **kwargs)
        return visited

    def visit_unhandled(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> Visited:
        
        log_debug(f"unhandled while tracing {src_ssa_var}: {expr.operation}, @0x{expr.address:x}\n{expr_path}")
        return Visited(VisitedResult.KILLED)

    #
    # MediumLevelIL SSA
    #

    def visit_MLIL_SSA(self, expr: MediumLevelILInstruction, *args, **kwargs) -> Visited:
        return super().visit_MLIL_SSA(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_SSA(
        self, expr: MediumLevelILSetVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> Visited:

        assert not expr_path

        expr_path += (expr.operation, )
        visited = self.visit(expr.src, src_ssa_var, *args, expr_path=expr_path, **kwargs)
        if not visited.result & VisitedResultFlag.VISITED:
            return visited

        definition = expr.dest
        uses = expr.function.ssa_form.get_ssa_var_uses(definition)
        if not uses:
            return Visited(VisitedResult.NO_USE, {definition: uses})

        return Visited(VisitedResult.VISITED, {definition: uses})

    def visit_MLIL_LOAD_SSA(
        self, expr: MediumLevelILLoadSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> Visited:

        expr_path += (expr.operation, )
        return self.visit(expr.src, src_ssa_var, *args, expr_path=expr_path, **kwargs)

    def visit_MLIL_VAR_SSA(
        self, expr: MediumLevelILVarSsa, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> Visited:

        assert expr_path

        if src_ssa_var != expr.src:
            return Visited(VisitedResult.KILLED)

        return Visited(VisitedResult.VISITED)

    def visit_MLIL_VAR_PHI(
        self, expr: MediumLevelILVarPhi, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs
        ) -> Visited:

        assert not expr_path

        if expr in self.visited:
            return Visited(VisitedResult.PASSED)

        # kind of cheat here :/
        for ssa_var in expr.src:
            self.graph.add_use(ssa_var, expr.dest)

        definition = expr.dest
        uses = expr.function.ssa_form.get_ssa_var_uses(definition)
        if not uses:
            return Visited(VisitedResult.NO_USE, {definition: uses})

        return Visited(VisitedResult.VISITED, {expr.dest: uses})

    #
    # MediumLevelIL
    #

    # ...

    #
    # MediumLevelIL Base
    #

    def visit_MLIL_UNARY_OP(
        self, expr: MediumLevelILUnaryBase, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs):
       
        assert expr_path
    
        if src_ssa_var not in (expr.vars_read + expr.vars_written):
            return Visited(VisitedResult.KILLED)

        expr_path += (expr.operation, )
        return self.visit(expr.src, src_ssa_var, *args, expr_path=expr_path, **kwargs)

    def visit_MLIL_BINARY_OP(
        self, expr: MediumLevelILBinaryBase, src_ssa_var: SSAVariable, *args,
        expr_path: Tuple[MediumLevelILOperation] = (), **kwargs):
    
        assert expr_path
    
        def_and_uses = {}

        left_expr_path = expr_path + (expr.operation, )
        visited_left = self.visit(expr.left, src_ssa_var, *args, expr_path=left_expr_path, **kwargs)
        def_and_uses.update(visited_left.def_and_uses)

        right_expr_path = expr_path + (expr.operation, )
        visited_right = self.visit(expr.right, src_ssa_var, *args, expr_path=right_expr_path, **kwargs)
        def_and_uses.update(visited_right.def_and_uses)

        if not (visited_left.result & VisitedResult.VISITED or visited_right.result & VisitedResult.VISITED):
            return Visited(VisitedResult.KILLED)

        return Visited(VisitedResult.VISITED, def_and_uses)
