from abc import ABC, abstractmethod

class VisitorBase(ABC):

    @abstractmethod
    def visit(self, *args, **kwargs):
        pass

    @abstractmethod
    def visit_unhandled(self, *args, **kwargs):
        pass

    @abstractmethod
    def visit_default(self, *args, **kwargs):
        pass