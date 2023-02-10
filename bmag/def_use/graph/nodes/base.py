from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import NamedTuple
    from .enums import NodeType
    NodeBaseType = NamedTuple('NodeBaseType', [('type', NodeType)])

from abc import ABC, abstractmethod


class NodeBase(ABC):

    @property
    @abstractmethod
    def label(self) -> str:
        ...