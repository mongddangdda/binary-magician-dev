from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Set, List, Dict
    from binaryninja import SSAVariable

from abc import ABC, abstractmethod
from typing import TypeVar, Generic
from dataclasses import dataclass
from collections import deque

from binaryninja import Function
from binaryninja.mediumlevelil import MediumLevelILOperation, MediumLevelILInstruction, MediumLevelILFunction
from binaryninja.highlevelil import HighLevelILOperation, HighLevelILInstruction, HighLevelILFunction

from bmag.def_use.base.expr_tracer import ExprTracer


BnIL            = TypeVar('BnIL', MediumLevelILInstruction, HighLevelILInstruction)
BnILOp          = TypeVar('BnILOp', MediumLevelILOperation, HighLevelILOperation)
BnILFunction    = TypeVar('BnILFunction', MediumLevelILFunction, HighLevelILFunction)
ExprTracerObj   = TypeVar('ExprTracerObj', bound=ExprTracer)


@dataclass(frozen=True)
class VisitSite(Generic[BnIL]):
    site        : BnIL        = None
    src_ssa_var : SSAVariable = None


class InstTracer(ABC, Generic[BnIL]):

    def __init__(self, function: Function | BnILFunction):

        if type(function) != Function:
            function = function.source_function

        self._function: Function = function

        self._expr_tracers: Dict[BnILOp, ExprTracerObj] = {}

        self._to_visit: List[VisitSite[BnIL]] = deque()
        self._coverage: List[BnIL] = deque()
        self._excludes: Set[BnIL] = set()

    @property
    def function(self):
        return self._function

    @property
    def func_mlil(self):
        return self.function.mlil

    @property
    def func_mlil_ssa(self):
        return self.func_mlil.ssa_form

    @property
    def func_hlil(self):
        return self.function.hlil

    @property
    def func_hlil_ssa(self):
        return self.func_hlil.ssa_form

    @property
    def to_visit(self):
        return self._to_visit

    @property
    def coverage(self):
        return self._coverage

    @property
    def excludes(self):
        return self._excludes

    def register_expr_tracer(self, op: BnILOp, expr_tracer: ExprTracerObj):
        if not isinstance(expr_tracer, ExprTracer):
            raise ValueError
        self._expr_tracers[op] = expr_tracer

    def get_expr_tracer(self, op: BnILOp):
        if op in self._expr_tracers and self._expr_tracers[op]:
            return self._expr_tracers[op]

    def add_site_to_visit(self, visit_site: VisitSite):
        self._to_visit.append(visit_site)

    def get_sites_to_visit(self, cond: VisitSite):
        for to_visit in self.to_visit:
            if cond.site == to_visit.site:
                if cond.src_ssa_var and cond.src_ssa_var == to_visit.src_ssa_var:
                    yield to_visit
                elif not cond.src_ssa_var:
                    yield to_visit
            elif cond.src_ssa_var == to_visit.src_ssa_var:
                if cond.site and cond.site == to_visit.site:
                    yield to_visit
                elif not cond.site:
                    yield to_visit

    def del_site_to_visit(self, cond: VisitSite):
        for del_visit in self.get_sites_to_visit(cond):
            self._to_visit = deque([visit_site for visit_site in self._to_visit if visit_site != del_visit])

    def clear_sites_to_visit(self):
        self._to_visit = deque()

    def visited(self, visit_site: VisitSite):
        self._coverage.append(visit_site)

    def clear_coverage(self):
        self._coverage = deque()

    def exclude(self, inst: BnIL):
        self._excludes.add(inst)

    def include(self, inst: BnIL):
        if inst in self.excludes:
            self._excludes.remove(inst)

    def clear_excludes(self):
        self._excludes.clear()

    def trace(self):

        while self.to_visit:

            visit_site = self._to_visit.pop()
            if visit_site.site in self.excludes:
                continue

            print(f"visiting : @ 0x{visit_site.site.address:x}, {visit_site.site.instr_index}")

            self.visit(visit_site)

            if (expr_tracer := self.get_expr_tracer(visit_site.site.operation)):
                expr_tracer.visit(visit_site.site, inst_tracer=self)

            self.visited(visit_site)

    @abstractmethod
    def visit(self, visit_site: VisitSite, *args, **kwargs) -> List[VisitSite]:
        ...

