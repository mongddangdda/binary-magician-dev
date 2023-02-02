from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Tuple
    from binaryninja import SSAVariable
    from binaryninja.mediumlevelil import *
    VisitSiteType = Tuple[MediumLevelILInstruction, SSAVariable]

from collections import deque

from binaryninja.log import log_warn

from bmag.visitor.mlil import MediumLevelILSsaVisitor
from ..visitor_result import VisitResult, VisitResultEnum, VisitResultFlag
from ..visitor_state import BeforeVisitState, AfterVisitState, QueryNextVisit


class MediumLevelILSsaDefUseFwdVisitor(MediumLevelILSsaVisitor):


    def __init__(self, function: MediumLevelILFunction):
        self._function = function
        self._visited: list[MediumLevelILInstruction] = None
        self._to_visit: deque[Tuple[MediumLevelILInstruction, SSAVariable]] = None
        self._next_visit: VisitSiteType = None


    @property
    def function(self) -> MediumLevelILFunction:
        return self._function

    @property
    def visited(self) -> List[MediumLevelILInstruction]:
        return self._visited

    @property
    def to_visit(self) -> deque[VisitSiteType]:
        return self._to_visit

    @property
    def next_visit(self) -> VisitSiteType:
        return self._next_visit


    def get_next_visit(self):
        self._next_visit = self.to_visit.pop()

    def throw_next_visit(self):
        self._next_visit = None

    def put_next_visit(self, site: MediumLevelILInstruction, src_var: SSAVariable):
        self._next_visit = (site, src_var)

    def query_next_visit(self, site: MediumLevelILInstruction, src_var: SSAVariable):
        self.to_visit.append((site, src_var))


    def trace(self, ssa_var: SSAVariable):

        assert self.function.ssa_form.get_ssa_var_definition(ssa_var)

        self._to_visit: deque[Tuple[MediumLevelILInstruction, SSAVariable]] = deque()
        self._visited: list[MediumLevelILInstruction] = deque()

        if not (uses := self.function.ssa_form.get_ssa_var_uses(ssa_var)):
            log_warn(f"mlil.ssa def-use fwd-trace failed: {ssa_var} has no uses.")
            raise StopIteration

        self._to_visit.extend([(site, ssa_var) for site in uses])

        while self.to_visit:

            self.get_next_visit()

            yield BeforeVisitState()

            if not self.next_visit:
                continue

            curr_site, src_ssa_var = self.next_visit

            visited = self.visit(curr_site, src_ssa_var)

            self._visited.append(curr_site)

            yield AfterVisitState(curr_site, visited, src_ssa_var)

            for src_var in visited.chains:
                for dst_var in visited.chains[src_var]:
                    for use in self.function.ssa_form.get_ssa_var_uses(dst_var):
                        self.query_next_visit(use, dst_var)
                        yield QueryNextVisit(use, src_var, dst_var)


    def visit(self, expr: MediumLevelILInstruction,
              src_ssa_var: SSAVariable, *args, **kwargs) -> VisitResult:

        return self.visit_MLIL_SSA(expr, src_ssa_var, *args, **kwargs)

    def visit_unhandled(self, expr: MediumLevelILInstruction,
                        src_ssa_var: SSAVariable, *args, **kwargs) -> VisitResult:
                    
        return VisitResult(VisitResultEnum.UNHANDLED, {})

    def visit_MLIL_SET_VAR_SSA(self, expr: MediumLevelILSetVarSsa,
                               src_ssa_var: SSAVariable, *args, **kwargs) -> VisitResult:

        visited = self.visit(expr.src, src_ssa_var, *args, **kwargs)
        if not (visited.result & VisitResultFlag.VISITED or visited.result == VisitResultEnum.UNHANDLED):
            return visited

        return VisitResult(VisitResultEnum.VISITED, {src_ssa_var: [expr.dest]})

    def visit_MLIL_VAR_PHI(self, expr: MediumLevelILVarPhi,
                           src_ssa_var: SSAVariable, *args, **kwargs) -> VisitResult:
        
        if expr in self.visited:
            return VisitResult(VisitResultEnum.PASSED, {})

        def_uses = {}

        # kind of cheat here :/
        for src_var in expr.src:
            def_uses[src_var] = [expr.dest]

        return VisitResult(VisitResultEnum.VISITED, def_uses)



