from abc import ABC
from binaryninja.mediumlevelil import *
from .common import CommonILVisitorMixin

class MediumLevelILVisitorMixin(CommonILVisitorMixin):

    def visit_MLIL_NOP(self, expr: MediumLevelILNop, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR(self, expr: MediumLevelILSetVar, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_FIELD(self, expr: MediumLevelILSetVarField, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SET_VAR_SPLIT(self, expr: MediumLevelILSetVarSplit, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_LOAD(self, expr: MediumLevelILLoad, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_LOAD_STRUCT(self, expr: MediumLevelILLoadStruct, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_STORE(self, expr: MediumLevelILStore, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_STORE_STRUCT(self, expr: MediumLevelILStoreStruct, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_VAR(self, expr: MediumLevelILVar, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_VAR_FIELD(self, expr: MediumLevelILVarField, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_VAR_SPLIT(self, expr: MediumLevelILVarSplit, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ADDRESS_OF(self, expr: MediumLevelILAddressOf, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ADDRESS_OF_FIELD(self, expr: MediumLevelILAddressOfField, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CONST(self, expr: MediumLevelILConst, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CONST_DATA(self, expr: MediumLevelILConstData, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CONST_PTR(self, expr: MediumLevelILConstPtr, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_EXTERN_PTR(self, expr: MediumLevelILExternPtr, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FLOAT_CONST(self, expr: MediumLevelILFloatConst, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_IMPORT(self, expr: MediumLevelILImport, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ADD(self, expr: MediumLevelILAdd, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ADC(self, expr: MediumLevelILAdc, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SUB(self, expr: MediumLevelILSub, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SBB(self, expr: MediumLevelILSbb, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_AND(self, expr: MediumLevelILAnd, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_OR(self, expr: MediumLevelILOr, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_XOR(self, expr: MediumLevelILXor, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_LSL(self, expr: MediumLevelILLsl, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_LSR(self, expr: MediumLevelILLsr, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ASR(self, expr: MediumLevelILAsr, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ROL(self, expr: MediumLevelILRol, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_RLC(self, expr: MediumLevelILRlc, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ROR(self, expr: MediumLevelILRor, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_RRC(self, expr: MediumLevelILRrc, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MUL(self, expr: MediumLevelILMul, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MULU_DP(self, expr: MediumLevelILMuluDp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MULS_DP(self, expr: MediumLevelILMulsDp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_DIVU(self, expr: MediumLevelILDivu, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_DIVU_DP(self, expr: MediumLevelILDivuDp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_DIVS(self, expr: MediumLevelILDivs, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_DIVS_DP(self, expr: MediumLevelILDivsDp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MODU(self, expr: MediumLevelILModu, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MODU_DP(self, expr: MediumLevelILModuDp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MODS(self, expr: MediumLevelILMods, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_MODS_DP(self, expr: MediumLevelILModsDp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_NEG(self, expr: MediumLevelILNeg, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_NOT(self, expr: MediumLevelILNot, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SX(self, expr: MediumLevelILSx, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ZX(self, expr: MediumLevelILZx, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_LOW_PART(self, expr: MediumLevelILLowPart, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_JUMP(self, expr: MediumLevelILJump, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_JUMP_TO(self, expr: MediumLevelILJumpTo, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_RET_HINT(self, expr: MediumLevelILRetHint, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CALL(self, expr: MediumLevelILCall, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CALL_UNTYPED(self, expr: MediumLevelILCallUntyped, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CALL_OUTPUT(self, expr: MediumLevelILCallOutput, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CALL_PARAM(self, expr: MediumLevelILCallParam, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_RET(self, expr: MediumLevelILRet, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_NORET(self, expr: MediumLevelILNoret, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_IF(self, expr: MediumLevelILIf, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_GOTO(self, expr: MediumLevelILGoto, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_E(self, expr: MediumLevelILCmpE, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_NE(self, expr: MediumLevelILCmpNe, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_SLT(self, expr: MediumLevelILCmpSlt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_ULT(self, expr: MediumLevelILCmpUlt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_SLE(self, expr: MediumLevelILCmpSle, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_ULE(self, expr: MediumLevelILCmpUle, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_SGE(self, expr: MediumLevelILCmpSge, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_UGE(self, expr: MediumLevelILCmpUge, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_SGT(self, expr: MediumLevelILCmpSgt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CMP_UGT(self, expr: MediumLevelILCmpUgt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_TEST_BIT(self, expr: MediumLevelILTestBit, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_BOOL_TO_INT(self, expr: MediumLevelILBoolToInt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ADD_OVERFLOW(self, expr: MediumLevelILAddOverflow, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SYSCALL(self, expr: MediumLevelILSyscall, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_SYSCALL_UNTYPED(self, expr: MediumLevelILSyscallUntyped, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_TAILCALL(self, expr: MediumLevelILTailcall, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_TAILCALL_UNTYPED(self, expr: MediumLevelILTailcallUntyped, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_INTRINSIC(self, expr: MediumLevelILIntrinsic, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FREE_VAR_SLOT(self, expr: MediumLevelILFreeVarSlot, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_BP(self, expr: MediumLevelILBp, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_TRAP(self, expr: MediumLevelILTrap, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_UNDEF(self, expr: MediumLevelILUndef, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_UNIMPL(self, expr: MediumLevelILUnimpl, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_UNIMPL_MEM(self, expr: MediumLevelILUnimplMem, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FADD(self, expr: MediumLevelILFadd, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FSUB(self, expr: MediumLevelILFsub, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FMUL(self, expr: MediumLevelILFmul, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FDIV(self, expr: MediumLevelILFdiv, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FSQRT(self, expr: MediumLevelILFsqrt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FNEG(self, expr: MediumLevelILFneg, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FABS(self, expr: MediumLevelILFabs, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FLOAT_TO_INT(self, expr: MediumLevelILFloatToInt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_INT_TO_FLOAT(self, expr: MediumLevelILIntToFloat, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FLOAT_CONV(self, expr: MediumLevelILFloatConv, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_ROUND_TO_INT(self, expr: MediumLevelILRoundToInt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FLOOR(self, expr: MediumLevelILFloor, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_CEIL(self, expr: MediumLevelILCeil, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FTRUNC(self, expr: MediumLevelILFtrunc, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_E(self, expr: MediumLevelILFcmpE, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_NE(self, expr: MediumLevelILFcmpNe, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_LT(self, expr: MediumLevelILFcmpLt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_LE(self, expr: MediumLevelILFcmpLe, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_GE(self, expr: MediumLevelILFcmpGe, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_GT(self, expr: MediumLevelILFcmpGt, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_O(self, expr: MediumLevelILFcmpO, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit_MLIL_FCMP_UO(self, expr: MediumLevelILFcmpUo, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)

    def visit(self, expr: MediumLevelILInstruction, *args, **kwargs):
        match expr.operation:
            case MediumLevelILOperation.MLIL_NOP:
                return self.visit_MLIL_NOP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SET_VAR:
                return self.visit_MLIL_SET_VAR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SET_VAR_FIELD:
                return self.visit_MLIL_SET_VAR_FIELD(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SET_VAR_SPLIT:
                return self.visit_MLIL_SET_VAR_SPLIT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_LOAD:
                return self.visit_MLIL_LOAD(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_LOAD_STRUCT:
                return self.visit_MLIL_LOAD_STRUCT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_STORE:
                return self.visit_MLIL_STORE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_STORE_STRUCT:
                return self.visit_MLIL_STORE_STRUCT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_VAR:
                return self.visit_MLIL_VAR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_VAR_FIELD:
                return self.visit_MLIL_VAR_FIELD(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_VAR_SPLIT:
                return self.visit_MLIL_VAR_SPLIT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ADDRESS_OF:
                return self.visit_MLIL_ADDRESS_OF(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
                return self.visit_MLIL_ADDRESS_OF_FIELD(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CONST:
                return self.visit_MLIL_CONST(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CONST_DATA:
                return self.visit_MLIL_CONST_DATA(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CONST_PTR:
                return self.visit_MLIL_CONST_PTR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_EXTERN_PTR:
                return self.visit_MLIL_EXTERN_PTR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FLOAT_CONST:
                return self.visit_MLIL_FLOAT_CONST(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_IMPORT:
                return self.visit_MLIL_IMPORT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ADD:
                return self.visit_MLIL_ADD(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ADC:
                return self.visit_MLIL_ADC(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SUB:
                return self.visit_MLIL_SUB(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SBB:
                return self.visit_MLIL_SBB(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_AND:
                return self.visit_MLIL_AND(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_OR:
                return self.visit_MLIL_OR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_XOR:
                return self.visit_MLIL_XOR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_LSL:
                return self.visit_MLIL_LSL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_LSR:
                return self.visit_MLIL_LSR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ASR:
                return self.visit_MLIL_ASR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ROL:
                return self.visit_MLIL_ROL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_RLC:
                return self.visit_MLIL_RLC(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ROR:
                return self.visit_MLIL_ROR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_RRC:
                return self.visit_MLIL_RRC(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MUL:
                return self.visit_MLIL_MUL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MULU_DP:
                return self.visit_MLIL_MULU_DP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MULS_DP:
                return self.visit_MLIL_MULS_DP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_DIVU:
                return self.visit_MLIL_DIVU(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_DIVU_DP:
                return self.visit_MLIL_DIVU_DP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_DIVS:
                return self.visit_MLIL_DIVS(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_DIVS_DP:
                return self.visit_MLIL_DIVS_DP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MODU:
                return self.visit_MLIL_MODU(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MODU_DP:
                return self.visit_MLIL_MODU_DP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MODS:
                return self.visit_MLIL_MODS(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_MODS_DP:
                return self.visit_MLIL_MODS_DP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_NEG:
                return self.visit_MLIL_NEG(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_NOT:
                return self.visit_MLIL_NOT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SX:
                return self.visit_MLIL_SX(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ZX:
                return self.visit_MLIL_ZX(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_LOW_PART:
                return self.visit_MLIL_LOW_PART(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_JUMP:
                return self.visit_MLIL_JUMP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_JUMP_TO:
                return self.visit_MLIL_JUMP_TO(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_RET_HINT:
                return self.visit_MLIL_RET_HINT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CALL:
                return self.visit_MLIL_CALL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CALL_UNTYPED:
                return self.visit_MLIL_CALL_UNTYPED(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CALL_OUTPUT:
                return self.visit_MLIL_CALL_OUTPUT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CALL_PARAM:
                return self.visit_MLIL_CALL_PARAM(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_RET:
                return self.visit_MLIL_RET(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_NORET:
                return self.visit_MLIL_NORET(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_IF:
                return self.visit_MLIL_IF(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_GOTO:
                return self.visit_MLIL_GOTO(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_E:
                return self.visit_MLIL_CMP_E(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_NE:
                return self.visit_MLIL_CMP_NE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_SLT:
                return self.visit_MLIL_CMP_SLT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_ULT:
                return self.visit_MLIL_CMP_ULT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_SLE:
                return self.visit_MLIL_CMP_SLE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_ULE:
                return self.visit_MLIL_CMP_ULE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_SGE:
                return self.visit_MLIL_CMP_SGE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_UGE:
                return self.visit_MLIL_CMP_UGE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_SGT:
                return self.visit_MLIL_CMP_SGT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CMP_UGT:
                return self.visit_MLIL_CMP_UGT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_TEST_BIT:
                return self.visit_MLIL_TEST_BIT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_BOOL_TO_INT:
                return self.visit_MLIL_BOOL_TO_INT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ADD_OVERFLOW:
                return self.visit_MLIL_ADD_OVERFLOW(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SYSCALL:
                return self.visit_MLIL_SYSCALL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_SYSCALL_UNTYPED:
                return self.visit_MLIL_SYSCALL_UNTYPED(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_TAILCALL:
                return self.visit_MLIL_TAILCALL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_TAILCALL_UNTYPED:
                return self.visit_MLIL_TAILCALL_UNTYPED(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_INTRINSIC:
                return self.visit_MLIL_INTRINSIC(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FREE_VAR_SLOT:
                return self.visit_MLIL_FREE_VAR_SLOT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_BP:
                return self.visit_MLIL_BP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_TRAP:
                return self.visit_MLIL_TRAP(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_UNDEF:
                return self.visit_MLIL_UNDEF(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_UNIMPL:
                return self.visit_MLIL_UNIMPL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_UNIMPL_MEM:
                return self.visit_MLIL_UNIMPL_MEM(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FADD:
                return self.visit_MLIL_FADD(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FSUB:
                return self.visit_MLIL_FSUB(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FMUL:
                return self.visit_MLIL_FMUL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FDIV:
                return self.visit_MLIL_FDIV(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FSQRT:
                return self.visit_MLIL_FSQRT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FNEG:
                return self.visit_MLIL_FNEG(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FABS:
                return self.visit_MLIL_FABS(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FLOAT_TO_INT:
                return self.visit_MLIL_FLOAT_TO_INT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_INT_TO_FLOAT:
                return self.visit_MLIL_INT_TO_FLOAT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FLOAT_CONV:
                return self.visit_MLIL_FLOAT_CONV(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_ROUND_TO_INT:
                return self.visit_MLIL_ROUND_TO_INT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FLOOR:
                return self.visit_MLIL_FLOOR(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_CEIL:
                return self.visit_MLIL_CEIL(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FTRUNC:
                return self.visit_MLIL_FTRUNC(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_E:
                return self.visit_MLIL_FCMP_E(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_NE:
                return self.visit_MLIL_FCMP_NE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_LT:
                return self.visit_MLIL_FCMP_LT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_LE:
                return self.visit_MLIL_FCMP_LE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_GE:
                return self.visit_MLIL_FCMP_GE(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_GT:
                return self.visit_MLIL_FCMP_GT(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_O:
                return self.visit_MLIL_FCMP_O(expr, *args, **kwargs)
            case MediumLevelILOperation.MLIL_FCMP_UO:
                return self.visit_MLIL_FCMP_UO(expr, *args, **kwargs)
            case _:
                return CommonILVisitorMixin.visit(self, expr, *args, **kwargs)