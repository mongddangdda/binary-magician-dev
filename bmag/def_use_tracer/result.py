from enum import IntEnum, IntFlag, auto
from .types import DefAndUsesDict


class VisitedResultFlag(IntFlag):
    VISITED = auto()
    NO_USE  = auto()
    KILLED  = auto()
    INVALID = auto()
    PASSED  = auto()


class VisitedResult(IntEnum):
    VISITED = VisitedResultFlag.VISITED
    NO_USE  = VisitedResultFlag.VISITED | VisitedResultFlag.NO_USE
    KILLED  = VisitedResultFlag.KILLED
    INVALID = VisitedResultFlag.KILLED  | VisitedResultFlag.INVALID
    PASSED  = VisitedResultFlag.PASSED


class Visited:

    def __init__(self, result: VisitedResult, def_and_uses: DefAndUsesDict = {}):
        self._result = result
        self._def_and_uses = def_and_uses

    def next_sites(self):
        for definition in self.def_and_uses:
            for use in self.def_and_uses[definition]:
                yield (use, definition)

    @property
    def result(self) -> VisitedResult:
        return self._result

    @property
    def def_and_uses(self) -> DefAndUsesDict:
        return self._def_and_uses


