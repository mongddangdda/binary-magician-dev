from abc import ABC

class BinaryNinjaILVisitor(ABC):

    def visit(self, expr, *args, **kwargs):
        self.visit_unhandled(expr, *args, **kwargs)

    def visit_unhandled(self, expr, *args, **kwargs):
        raise NotImplementedError