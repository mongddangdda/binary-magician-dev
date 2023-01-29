from typing import Dict, List
from binaryninja import SSAVariable, MediumLevelILInstruction

DefAndUsesDict = Dict[SSAVariable, List[MediumLevelILInstruction]]