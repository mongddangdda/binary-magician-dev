from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja.mediumlevelil import (
        MediumLevelILInstruction,
        MediumLevelILSetVarSsa,
        MediumLevelILVarPhi,
        MediumLevelILCallBase,
        MediumLevelILIf
    )
    from def_use.base.inst_tracer import Function, BnILFunction

from binaryninja import log_warn

from bmag.def_use.graph import Graph, CalledNode, KilledNode, UnhandledNode, SsaVarDefNode
from bmag.def_use.base.inst_tracer import InstTracer, VisitSite
from bmag.visitor.mlil.ssa import MediumLevelILSsaVisitor as MLILSsaVisitor


class MLILSsaFwdTracer(InstTracer, MLILSsaVisitor):

    def __init__(self, function: Function | BnILFunction):
        super().__init__(function)
        self._graph = None

    @property
    def graph(self):
        if hasattr(self, '_graph'):
            return self._graph

    def set_graph(self, graph: Graph):
        self._graph = graph

    def unset_graph(self):
        self._graph = None

    def trace(self):
        return super().trace()

    def visit(self, visit_site: VisitSite, *args, **kwargs):
        return self.visit_MLIL_SSA(visit_site.site, visit_site, *args, **kwargs)

    def visit_unhandled(self, inst: MediumLevelILInstruction, visit_site: VisitSite, *args, **kwargs):

        log_warn(f"{inst.operation.name} is not handled.")

        if self.graph:
            self.graph.add_edge(
                SsaVarDefNode(ssa_var=visit_site.src_ssa_var),
                UnhandledNode(site=inst)
            )

    def visit_MLIL_SET_VAR_SSA(self, inst: MediumLevelILSetVarSsa, visit_site: VisitSite, *args, **kwargs):

        if self.graph:
            self.graph.add_edge(
                SsaVarDefNode(ssa_var=visit_site.src_ssa_var),
                SsaVarDefNode(ssa_var=inst.dest)
            )

        for use in self.func_mlil_ssa.get_ssa_var_uses(inst.dest):
            self.add_site_to_visit(VisitSite(
                site = use, 
                src_ssa_var = inst.dest
            ))
        
    def visit_MLIL_VAR_PHI(self, inst: MediumLevelILVarPhi, visit_site: VisitSite, *args, **kwargs):

        if self.graph:
            dst_node = SsaVarDefNode(ssa_var=inst.dest)
            for src_ssa_var in inst.src:
                self.graph.add_edge(SsaVarDefNode(ssa_var=src_ssa_var), dst_node)

        for use in self.func_mlil_ssa.get_ssa_var_uses(inst.dest):
            self.add_site_to_visit(VisitSite(
                site = use,
                src_ssa_var = inst.dest
            ))

        self.exclude(inst)

    def visit_MLIL_CALL_OP(self, inst: MediumLevelILCallBase, visit_site: VisitSite, *args, **kwargs):
        if self.graph:
            self.graph.add_edge(
                SsaVarDefNode(ssa_var=visit_site.src_ssa_var),
                CalledNode(site=inst)
            )

    def visit_MLIL_IF(self, inst: MediumLevelILIf, visit_site: VisitSite, *args, **kwargs):
        if self.graph:
            self.graph.add_edge(
                SsaVarDefNode(ssa_var=visit_site.src_ssa_var),
                KilledNode(site=inst)
            )
