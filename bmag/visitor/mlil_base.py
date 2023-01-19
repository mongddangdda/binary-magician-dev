from binaryninja.mediumlevelil import *
from bmag.visitor.base import VisitorBase

class MediumLevelILBaseVisitorMixin(VisitorBase):

    def visit_MLIL_UNARY_OP(self, expr: MediumLevelILUnaryBase, *args, **kwargs):
        return self.visit_unhandled(expr, *args, **kwargs)

    def visit_MLIL_BINARY_OP(self, expr: MediumLevelILBinaryBase, *args, **kwargs):
        return self.visit_unhandled(expr, *args, **kwargs)

    def visit_MLIL_CALL_OP(self, expr: MediumLevelILCallBase, *args, **kwargs):
        return self.visit_unhandled(expr, *args, **kwargs)

    def visit_MLIL_CARRY_OP(self, expr: MediumLevelILCarryBase, *args, **kwargs):
        return self.visit_unhandled(expr, *args, **kwargs)

    def visit_MLIL_CONST_OP(self, expr: MediumLevelILConstBase, *args, **kwargs):
        return self.visit_unhandled(expr, *args, **kwargs)

    def visit_MLIL_COMPARISON_OP(self, expr: MediumLevelILComparisonBase, *args, **kwargs):
        return self.visit_unhandled(expr, *args, **kwargs)

    def visit_default(self, expr: MediumLevelILInstruction, *args, **kwargs):

        match expr.operation:

            case MediumLevelILOperation.MLIL_NOP:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_SPLIT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOAD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOAD_STRUCT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_STORE:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_STORE_STRUCT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SPLIT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ADDRESS_OF:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CONST:
                return self.visit_MLIL_CONST_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CONST_DATA:
                return self.visit_MLIL_CONST_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CONST_PTR:
                return self.visit_MLIL_CONST_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_EXTERN_PTR:
                return self.visit_MLIL_CONST_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FLOAT_CONST:
                return self.visit_MLIL_CONST_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_IMPORT:
                return self.visit_MLIL_CONST_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ADD:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ADC:
                return self.visit_MLIL_CARRY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SUB:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SBB:
                return self.visit_MLIL_CARRY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_AND:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_OR:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_XOR:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LSL:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LSR:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ASR:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ROL:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_RLC:
                return self.visit_MLIL_CARRY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ROR:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_RRC:
                return self.visit_MLIL_CARRY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MUL:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MULU_DP:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MULS_DP:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_DIVU:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_DIVU_DP:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_DIVS:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_DIVS_DP:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MODU:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MODU_DP:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MODS:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MODS_DP:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_NEG:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_NOT:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SX:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ZX:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOW_PART:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_JUMP:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_JUMP_TO:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_RET_HINT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_UNTYPED:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_OUTPUT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_PARAM:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_RET:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_NORET:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_IF:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_GOTO:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_E:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_NE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_SLT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_ULT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_SLE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_ULE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_SGE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_UGE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_SGT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CMP_UGT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TEST_BIT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_BOOL_TO_INT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ADD_OVERFLOW:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SYSCALL:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SYSCALL_UNTYPED:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TAILCALL:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TAILCALL_UNTYPED:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_INTRINSIC:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FREE_VAR_SLOT:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_BP:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TRAP:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_UNDEF:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_UNIMPL:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_UNIMPL_MEM:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FADD:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FSUB:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FMUL:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FDIV:
                return self.visit_MLIL_BINARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FSQRT:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FNEG:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FABS:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FLOAT_TO_INT:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_INT_TO_FLOAT:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FLOAT_CONV:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_ROUND_TO_INT:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FLOOR:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CEIL:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FTRUNC:
                return self.visit_MLIL_UNARY_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_E:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_NE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_LT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_LE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_GE:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_GT:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_O:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FCMP_UO:
                return self.visit_MLIL_COMPARISON_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_ALIASED:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_SPLIT_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_SSA:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SYSCALL_SSA:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TAILCALL_SSA:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA:
                return self.visit_MLIL_CALL_OP(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_PARAM_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOAD_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_STORE_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_INTRINSIC_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_VAR_PHI:
                return self.visit_unhandled(expr, *args, **kwargs)

            case MediumLevelILOperation.MLIL_MEM_PHI:
                return self.visit_unhandled(expr, *args, **kwargs)

            case _:
                return self.visit_unhandled(expr, *args, **kwargs)

    def visit(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_default(expr, *args, **kwargs)