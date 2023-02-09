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

from bmag.def_use.base.inst_tracer import InstTracer, VisitSite
from bmag.visitor.mlil.ssa import MediumLevelILSsaVisitor as BaseVisitor
from bmag.def_use.graph import NodeTypes


class MLILSsaFwdInstTracer(InstTracer, BaseVisitor):

    def trace(self):
        return super().trace()

    def visit(self, visit_site: VisitSite, *args, **kwargs):
        return self.visit_MLIL_SSA(visit_site.site, visit_site, *args, **kwargs)

    def visit_unhandled(self, inst: MediumLevelILInstruction, visit_site: VisitSite, *args, **kwargs):
        if self.graph_enabled:
            src_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF,   visit_site.src_ssa_var, exists_ok=True) 
            dst_node = self.def_use_graph.add_node(NodeTypes.UNHANDLED, inst,                   exists_ok=True)
            self.def_use_graph.add_edge(src_node, dst_node)

    def visit_MLIL_SET_VAR_SSA(self, inst: MediumLevelILSetVarSsa, visit_site: VisitSite, *args, **kwargs):

        if self.graph_enabled:
            src_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF, visit_site.src_ssa_var, exists_ok=True) 
            dst_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF, inst.dest,              exists_ok=True)
            self.def_use_graph.add_edge(src_node, dst_node)

        for use in self.func_mlil_ssa.get_ssa_var_uses(inst.dest):
            self.add_site_to_visit(VisitSite(
                site = use, 
                src_ssa_var = inst.dest
            ))
        
    def visit_MLIL_VAR_PHI(self, inst: MediumLevelILVarPhi, visit_site: VisitSite, *args, **kwargs):

        if self.graph_enabled:

            dst_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF, inst.dest, exists_ok=True)

            for src_ssa_var in inst.src:
                src_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF, src_ssa_var, exists_ok=True) 
                self.def_use_graph.add_edge(src_node, dst_node)

        for use in self.func_mlil_ssa.get_ssa_var_uses(inst.dest):
            self.add_site_to_visit(VisitSite(
                site = use,
                src_ssa_var = inst.dest
            ))

        self.exclude(inst)

    def visit_MLIL_CALL_OP(self, inst: MediumLevelILCallBase, visit_site: VisitSite, *args, **kwargs):
        if self.graph_enabled:
            src_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF, visit_site.src_ssa_var, exists_ok=True) 
            dst_node = self.def_use_graph.add_node(NodeTypes.CALLED,  inst,                   exists_ok=True)
            self.def_use_graph.add_edge(src_node, dst_node)

    def visit_MLIL_IF(self, inst: MediumLevelILIf, visit_site: VisitSite, *args, **kwargs):
        if self.graph_enabled:
            src_node = self.def_use_graph.add_node(NodeTypes.SSA_DEF, visit_site.src_ssa_var, exists_ok=True) 
            dst_node = self.def_use_graph.add_node(NodeTypes.KILLED,  inst,                   exists_ok=True)
            self.def_use_graph.add_edge(src_node, dst_node)

