from binaryninja.mediumlevelil import *
from bmag.visitor.mlil import MediumLevelILVisitorMixin

class MediumLevelILSsaVisitorMixin(MediumLevelILVisitorMixin):

    def visit_MLIL_SET_VAR_SSA(self, expr: MediumLevelILSetVarSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_SSA_FIELD(self, expr: MediumLevelILSetVarSsaField, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_SPLIT_SSA(self, expr: MediumLevelILSetVarSplitSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_ALIASED(self, expr: MediumLevelILSetVarAliased, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_ALIASED_FIELD(self, expr: MediumLevelILSetVarAliasedField, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_VAR_SSA(self, expr: MediumLevelILVarSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_VAR_SSA_FIELD(self, expr: MediumLevelILVarSsaField, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_VAR_ALIASED(self, expr: MediumLevelILVarAliased, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_VAR_ALIASED_FIELD(self, expr: MediumLevelILVarAliasedField, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_VAR_SPLIT_SSA(self, expr: MediumLevelILVarSplitSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_CALL_SSA(self, expr: MediumLevelILCallSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_CALL_UNTYPED_SSA(self, expr: MediumLevelILCallUntypedSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_SYSCALL_SSA(self, expr: MediumLevelILSyscallSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_SYSCALL_UNTYPED_SSA(self, expr: MediumLevelILSyscallUntypedSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_TAILCALL_SSA(self, expr: MediumLevelILTailcallSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_TAILCALL_UNTYPED_SSA(self, expr: MediumLevelILTailcallUntypedSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_CALL_PARAM_SSA(self, expr: MediumLevelILCallParamSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_CALL_OUTPUT_SSA(self, expr: MediumLevelILCallOutputSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_LOAD_SSA(self, expr: MediumLevelILLoadSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_LOAD_STRUCT_SSA(self, expr: MediumLevelILLoadStructSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_STORE_SSA(self, expr: MediumLevelILStoreSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_STORE_STRUCT_SSA(self, expr: MediumLevelILStoreStructSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_INTRINSIC_SSA(self, expr: MediumLevelILIntrinsicSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_FREE_VAR_SLOT_SSA(self, expr: MediumLevelILFreeVarSlotSsa, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_VAR_PHI(self, expr: MediumLevelILVarPhi, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit_MLIL_MEM_PHI(self, expr: MediumLevelILMemPhi, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)

    def visit(self, expr: MediumLevelILInstruction, *args, **kwargs):

        match expr.operation:

            case MediumLevelILOperation.MLIL_SET_VAR_SSA:
                return self.visit_MLIL_SET_VAR_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
                return self.visit_MLIL_SET_VAR_SSA_FIELD(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
                return self.visit_MLIL_SET_VAR_SPLIT_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                return self.visit_MLIL_SET_VAR_ALIASED(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
                return self.visit_MLIL_SET_VAR_ALIASED_FIELD(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SSA:
                return self.visit_MLIL_VAR_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
                return self.visit_MLIL_VAR_SSA_FIELD(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_ALIASED:
                return self.visit_MLIL_VAR_ALIASED(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
                return self.visit_MLIL_VAR_ALIASED_FIELD(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SPLIT_SSA:
                return self.visit_MLIL_VAR_SPLIT_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_SSA:
                return self.visit_MLIL_CALL_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA:
                return self.visit_MLIL_CALL_UNTYPED_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SYSCALL_SSA:
                return self.visit_MLIL_SYSCALL_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA:
                return self.visit_MLIL_SYSCALL_UNTYPED_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TAILCALL_SSA:
                return self.visit_MLIL_TAILCALL_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA:
                return self.visit_MLIL_TAILCALL_UNTYPED_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_PARAM_SSA:
                return self.visit_MLIL_CALL_PARAM_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:
                return self.visit_MLIL_CALL_OUTPUT_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOAD_SSA:
                return self.visit_MLIL_LOAD_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
                return self.visit_MLIL_LOAD_STRUCT_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_STORE_SSA:
                return self.visit_MLIL_STORE_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
                return self.visit_MLIL_STORE_STRUCT_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_INTRINSIC_SSA:
                return self.visit_MLIL_INTRINSIC_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA:
                return self.visit_MLIL_FREE_VAR_SLOT_SSA(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_PHI:
                return self.visit_MLIL_VAR_PHI(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MEM_PHI:
                return self.visit_MLIL_MEM_PHI(expr, *args, **kwargs)

            case _:
                return MediumLevelILVisitorMixin.visit(self, expr, *args, **kwargs)

