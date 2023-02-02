from enum import IntFlag, IntEnum, auto


class NodeTypeFlags(IntFlag):
    DEF = auto()
    END = auto()
    CALLED = auto()
    KILLED = auto()
    NO_USE = auto()


class EdgeTypeFlags(IntFlag):
    USE = auto()


class NodeTypes(IntEnum):
    DEF = NodeTypeFlags.DEF
    END = NodeTypeFlags.END
    CALLED = NodeTypeFlags.CALLED | NodeTypeFlags.END
    KILLED = NodeTypeFlags.KILLED | NodeTypeFlags.END
    NO_USE = NodeTypeFlags.NO_USE | NodeTypeFlags.END


class EdgeTypes(IntEnum):
    USE = EdgeTypeFlags.USE

