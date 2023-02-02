from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import *


from abc import ABC
from ..base import BaseNode


class DefUseCalledNode(BaseNode):
    pass


class DefUseGraphCalledMixin(ABC):

    @property
    def ends_with_called(self):
        ...

    def add_end_with_called(self):
        ...

