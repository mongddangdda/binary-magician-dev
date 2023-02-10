from enum import IntFlag, IntEnum, auto


class NodeTypeFlag(IntFlag):
    VAR_TYPE = auto()
    MEM_TYPE = auto()
    SSA_TYPE = auto()
    SITE_TYPE = auto()
    DEF = auto()
    CALLED = auto()
    KILLED = auto()
    UNHANDLED = auto()


class NodeType(IntEnum):
    SSA_VAR_DEF = NodeTypeFlag.SSA_TYPE | NodeTypeFlag.VAR_TYPE | NodeTypeFlag.DEF
    CALLED = NodeTypeFlag.SITE_TYPE | NodeTypeFlag.CALLED
    KILLED = NodeTypeFlag.SITE_TYPE | NodeTypeFlag.KILLED
    UNHANDLED = NodeTypeFlag.SITE_TYPE | NodeTypeFlag.SITE_TYPE
