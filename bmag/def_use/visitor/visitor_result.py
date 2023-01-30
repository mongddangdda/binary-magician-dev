#
#
#

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import List, Dict
    from binaryninja import SSAVariable


from dataclasses import dataclass
from enum import IntEnum, IntFlag, auto


class VisitResultFlag(IntFlag):
    VISITED = auto()
    NO_USE  = auto()
    KILLED  = auto()
    INVALID = auto()
    PASSED  = auto()
    UNHANDLED = auto()


class VisitResultEnum(IntEnum):
    VISITED   = VisitResultFlag.VISITED
    NO_USE    = VisitResultFlag.VISITED | VisitResultFlag.NO_USE
    KILLED    = VisitResultFlag.KILLED
    INVALID   = VisitResultFlag.KILLED | VisitResultFlag.INVALID
    PASSED    = VisitResultFlag.PASSED
    UNHANDLED = VisitResultFlag.PASSED | VisitResultFlag.UNHANDLED


@dataclass(frozen=True)
class VisitResult:
    result: VisitResultEnum
    chains: Dict[SSAVariable, List[SSAVariable]]

