from abc import ABC, abstractmethod

from binaryninja.mediumlevelil import *
from binaryninja.commonil import *

class CommonILVisitorMixin(ABC):

    @abstractmethod
    def visit_Generic(self, expr: MediumLevelILInstruction, *args, **kwargs):
        ...

    def visit_Arithmetic(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Carry(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Arithmetic(expr, *args, **kwargs)

    def visit_DoublePrecision(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Arithmetic(expr, *args, **kwargs)

    def visit_BinaryOperation(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Comparison(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_BinaryOperation(expr, *args, **kwargs)

    def visit_Controlflow(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Call(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Controlflow(expr, *args, **kwargs)

    def visit_Localcall(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Call(expr, *args, **kwargs)

    def visit_Syscall(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Call(expr, *args, **kwargs)

    def visit_Tailcall(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Localcall(expr, *args, **kwargs)

    def visit_Loop(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Controlflow(expr, *args, **kwargs)

    def visit_Terminal(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Controlflow(expr, *args, **kwargs)

    def visit_Return(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Terminal(expr, *args, **kwargs)

    def visit_Constant(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_FloatingPoint(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Intrinsic(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Load(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Memory(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_RegisterStack(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_SetReg(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_SetVar(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Signed(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_StackOperation(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Store(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_UnaryOperation(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_SSA(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_Generic(expr, *args, **kwargs)

    def visit_Phi(self, expr: MediumLevelILInstruction, *args, **kwargs):
        return self.visit_SSA(expr, *args, **kwargs)

    def visit_Default(self, expr: MediumLevelILInstruction, *args, **kwargs):
        if isinstance(expr, Arithmetic):
            return self.visit_Arithmetic(expr, *args, **kwargs)
        elif isinstance(expr, BinaryOperation):
            return self.visit_BinaryOperation(expr, *args, **kwargs)
        elif isinstance(expr, Call):
            return self.visit_Call(expr, *args, **kwargs)
        elif isinstance(expr, Carry):
            return self.visit_Carry(expr, *args, **kwargs)
        elif isinstance(expr, Comparison):
            return self.visit_Comparison(expr, *args, **kwargs)
        elif isinstance(expr, Constant):
            return self.visit_Constant(expr, *args, **kwargs)
        elif isinstance(expr, ControlFlow):
            return self.visit_Controlflow(expr, *args, **kwargs)
        elif isinstance(expr, DoublePrecision):
            return self.visit_DoublePrecision(expr, *args, **kwargs)
        elif isinstance(expr, FloatingPoint):
            return self.visit_FloatingPoint(expr, *args, **kwargs)
        elif isinstance(expr, Intrinsic):
            return self.visit_Intrinsic(expr, *args, **kwargs)
        elif isinstance(expr, Load):
            return self.visit_Load(expr, *args, **kwargs)
        elif isinstance(expr, Localcall):
            return self.visit_Localcall(expr, *args, **kwargs)
        elif isinstance(expr, Loop):
            return self.visit_Loop(expr, *args, **kwargs)
        elif isinstance(expr, Memory):
            return self.visit_Memory(expr, *args, **kwargs)
        elif isinstance(expr, Phi):
            return self.visit_Phi(expr, *args, **kwargs)
        elif isinstance(expr, RegisterStack):
            return self.visit_RegisterStack(expr, *args, **kwargs)
        elif isinstance(expr, Return):
            return self.visit_Return(expr, *args, **kwargs)
        elif isinstance(expr, SSA):
            return self.visit_SSA(expr, *args, **kwargs)
        elif isinstance(expr, SetReg):
            return self.visit_SetReg(expr, *args, **kwargs)
        elif isinstance(expr, SetVar):
            return self.visit_SetVar(expr, *args, **kwargs)
        elif isinstance(expr, Signed):
            return self.visit_Signed(expr, *args, **kwargs)
        elif isinstance(expr, StackOperation):
            return self.visit_StackOperation(expr, *args, **kwargs)
        elif isinstance(expr, Store):
            return self.visit_Store(expr, *args, **kwargs)
        elif isinstance(expr, Syscall):
            return self.visit_Syscall(expr, *args, **kwargs)
        elif isinstance(expr, Tailcall):
            return self.visit_Tailcall(expr, *args, **kwargs)
        elif isinstance(expr, Terminal):
            return self.visit_Terminal(expr, *args, **kwargs)
        elif isinstance(expr, UnaryOperation):
            return self.visit_UnaryOperation(expr, *args, **kwargs)
        else:
            return self.visit_Generic(expr, *args, **kwargs)

    def visit(self, *args, **kwargs):
        return self.visit_Default(*args, **kwargs)