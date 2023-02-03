from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from binaryninja.mediumlevelil import MediumLevelILInstruction
    from binaryninja.highlevelil import HighLevelILInstruction
    AboveMediumIL = MediumLevelILInstruction | HighLevelILInstruction
