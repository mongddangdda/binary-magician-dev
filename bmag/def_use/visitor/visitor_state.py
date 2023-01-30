from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Any
    from binaryninja import SSAVariable
    from .visitor_result import VisitResult


from enum import IntEnum, IntFlag, auto
from dataclasses import dataclass


class VisitorStateFlag(IntFlag):
    INCOMPLETE = auto()
    BEFORE_VISIT = auto()
    AFTER_VISIT = auto()
    QUERY_NEXT = auto()


class VisitorStateEnum(IntEnum):
    INCOMPLETE     = VisitorStateFlag.INCOMPLETE
    BEFORE_VISIT = VisitorStateFlag.BEFORE_VISIT
    AFTER_VISIT  = VisitorStateFlag.AFTER_VISIT
    QUERY_NEXT   = VisitorStateFlag.AFTER_VISIT | VisitorStateFlag.QUERY_NEXT


@dataclass(frozen=True)
class VisitorState:
    state: VisitorStateEnum


@dataclass(frozen=True)
class IncompleteState:
    reason: str
    state = VisitorStateEnum.INCOMPLETE


@dataclass(frozen=True)
class BeforeVisitState:
    state = VisitorStateEnum.BEFORE_VISIT

@dataclass(frozen=True)
class AfterVisitState:
    site: Any
    result: VisitResult
    src_var: Any = None
    dst_var: Any = None
    state = VisitorStateEnum.AFTER_VISIT

@dataclass(frozen=True)
class QueryNextVisit:
    site: Any
    src_var: Any
    dst_var: Any
    state = VisitorStateEnum.QUERY_NEXT

