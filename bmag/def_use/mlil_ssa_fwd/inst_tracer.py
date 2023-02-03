from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import List, Set
    from binaryninja import SSAVariable
    from binaryninja.mediumlevelil import (
        MediumLevelILInstruction,
        MediumLevelILSetVarSsa,
        MediumLevelILVarPhi
    )


from collections import deque
from dataclasses import dataclass

from binaryninja import Function

from bmag.visitor.mlil.ssa import MediumLevelILSsaVisitor as BaseVisitor
from bmag.def_use.graph import NodeTypes, NodeTypeFlags
from bmag.def_use.graph import DefUseGraph
from bmag.def_use.graph import CalledNode, KilledNode, SsaDefNode, UnhandledNode


@dataclass(frozen=True)
class VisitSite:
    site        : MediumLevelILInstruction  = None
    src_ssa_var : SSAVariable               = None


class FwdInstTracer(BaseVisitor):

    def __init__(self, function: Function,
                 expr_visitor_cls: object = None,
                 call_visitor_cls: object = None,
                 def_use_graph: DefUseGraph = None):

        if type(function) != Function:
            function = function.source_function

        if not expr_visitor_cls:
            pass

        if not call_visitor_cls:
            pass

        if not def_use_graph:
            def_use_graph = DefUseGraph()

        self._function: Function = function
        self._expr_visitor_cls: object = expr_visitor_cls
        self._def_use_graph: DefUseGraph = def_use_graph

        self._to_visit: List[VisitSite] = deque()
        self._coverage: List[MediumLevelILInstruction] = deque()
        self._excludes: Set[MediumLevelILInstruction] = set()

    @property
    def function(self):
        return self._function

    @property
    def func_mlil(self):
        return self.function.mlil

    @property
    def func_mlil_ssa(self):
        return self.function.mlil.ssa_form

    @property
    def def_use_graph(self):
        return self._def_use_graph

    @property
    def to_visit(self):
        return self._to_visit

    @property
    def coverage(self):
        return self._coverage

    @property
    def excludes(self):
        return self._excludes

    @property
    def expr_visitor_cls(self):
        return self._expr_visitor_cls

    def add_site_to_visit(self, visit_site: VisitSite):
        assert visit_site.site.function == self.func_mlil_ssa
        assert self.func_mlil_ssa.get_ssa_var_definition(visit_site.src_ssa_var)
        self._to_visit.append(visit_site)

    def get_sites_to_visit(self, query: VisitSite):
        assert query.site or query.src_ssa_var
        for to_visit in self.to_visit:
            if query.site == to_visit.site:
                if query.src_ssa_var and query.src_ssa_var == to_visit.src_ssa_var:
                    yield to_visit
                elif not query.src_ssa_var:
                    yield to_visit
            elif query.src_ssa_var == to_visit.src_ssa_var:
                if query.site and query.site == to_visit.site:
                    yield to_visit
                elif not query.site:
                    yield to_visit

    def del_site_to_visit(self, query: VisitSite):
        for del_visit in self.get_sites_to_visit(query):
            self._to_visit = deque([visit_site for visit_site in self._to_visit if visit_site != del_visit])

    def clear_sites_to_visit(self):
        self._to_visit = deque()

    def visited(self, visit_site: VisitSite):
        assert visit_site.site.function == self.func_mlil_ssa
        self._coverage.append(visit_site)

    def clear_coverage(self):
        self._coverage = deque()

    def exclude(self, inst: MediumLevelILInstruction):
        assert inst.function == self.func_mlil_ssa
        self._excludes.add(inst)

    def include(self, inst: MediumLevelILInstruction):
        assert inst.function == self.func_mlil_ssa
        if inst in self.excludes:
            self._excludes.remove(inst)

    def clear_excludes(self):
        self._excludes.clear()

    def trace(self, visit_site: VisitSite = None, src_ssa_var: SSAVariable = None):

        self.clear_sites_to_visit()

        if visit_site:
            assert visit_site.site.function == self.func_mlil_ssa
            assert visit_site.src_ssa_var.function == self.function
            src_ssa_var = visit_site.src_ssa_var
            self.add_site_to_visit(VisitSite(use, src_ssa_var))
        elif src_ssa_var:
            assert src_ssa_var.function == self.function
            assert self.func_mlil_ssa.get_ssa_var_definition(src_ssa_var)
            for use in self.func_mlil_ssa.get_ssa_var_uses(src_ssa_var):
                self.add_site_to_visit(VisitSite(use, src_ssa_var))
        else:
            raise Exception

        self.def_use_graph.add_ssa_def_node(src_ssa_var)

        while self.to_visit:
            visit_site = self._to_visit.pop()
            if visit_site.site not in self.excludes:
                print(f"visiting : @ 0x{visit_site.site.address:x}, {visit_site.site.instr_index}")
                self.visit(visit_site)
                self.visited(visit_site)

    def visit(self, visit_site: VisitSite, *args, **kwargs):
        return self.visit_MLIL_SSA(visit_site.site, visit_site, *args, **kwargs)

    def visit_unhandled(self, inst: MediumLevelILInstruction, visit_site: VisitSite, *args, **kwargs):

        if not (src_node := self.def_use_graph.has_node(NodeTypes.SSA_DEF, visit_site.src_ssa_var)):
            raise ValueError

        dst_node = self.def_use_graph.add_unhandled_node(inst)
        
        self.def_use_graph.chain(src_node, dst_node)

        return dst_node

    def visit_MLIL_SET_VAR_SSA(self, inst: MediumLevelILSetVarSsa, visit_site: VisitSite, *args, **kwargs):
        
        if not (src_node := self.def_use_graph.has_node(NodeTypes.SSA_DEF, visit_site.src_ssa_var)):
            raise ValueError

        dst_node = self.def_use_graph.add_ssa_def_node(inst.dest)

        self.def_use_graph.chain(src_node, dst_node)

        for use in self.func_mlil_ssa.get_ssa_var_uses(inst.dest):
            self.add_site_to_visit(VisitSite(
                site = use, 
                src_ssa_var = inst.dest 
            ))

        return dst_node
        
    def visit_MLIL_VAR_PHI(self, inst: MediumLevelILVarPhi, visit_site: VisitSite, *args, **kwargs):

        dst_node = self.def_use_graph.add_ssa_def_node(inst.dest)

        for src_ssa_var in inst.src:
            if not (src_node := self.def_use_graph.has_node(NodeTypes.SSA_DEF, src_ssa_var)):
                src_node = self.def_use_graph.add_ssa_def_node(src_ssa_var)
            self.def_use_graph.chain(src_node, dst_node)

        for use in self.func_mlil_ssa.get_ssa_var_uses(inst.dest):
            self.add_site_to_visit(VisitSite(
                site = use,
                src_ssa_var = inst.dest
            ))

        self.exclude(inst)

        return dst_node

