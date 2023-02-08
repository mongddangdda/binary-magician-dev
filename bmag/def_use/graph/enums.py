from enum import IntFlag, IntEnum, auto


class NodeTypeFlags(IntFlag):
    VAR         = auto()
    SSA_VAR     = auto()
    SITE        = auto()
    DEF         = auto()
    CALLED      = auto()
    KILLED      = auto()
    UNHANDLED   = auto()


class NodeTypes(IntEnum):
    DEF       = NodeTypeFlags.VAR     | NodeTypeFlags.DEF
    SSA_DEF   = NodeTypeFlags.SSA_VAR | NodeTypeFlags.DEF
    CALLED    = NodeTypeFlags.SITE    | NodeTypeFlags.CALLED 
    KILLED    = NodeTypeFlags.SITE    | NodeTypeFlags.KILLED
    UNHANDLED = NodeTypeFlags.SITE    | NodeTypeFlags.UNHANDLED

