#
#
#


from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:

    from typing import Type

    from binaryninja import SSAVariable
    from binaryninja.mediumlevelil import MediumLevelILInstruction
    from binaryninja.highlevelil import HighLevelILInstruction

    from networkx import DiGraph

    from . import DefUseGraph
    from .enums import NodeTypeFlags, NodeTypes, EdgeTypeFlags, EdgeTypes
    from .base import BaseNode, BaseEdge
    from .leaves import KilledNode, NoUseNode

    AboveMediumIL = MediumLevelILInstruction | HighLevelILInstruction
