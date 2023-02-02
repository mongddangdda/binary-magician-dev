from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .types import *
    from typing import Dict, Tuple, Any


from abc import ABC, abstractmethod
from .enums import NodeTypes, EdgeTypes


class BaseNode(ABC):

    @classmethod
    @abstractmethod
    def create(cls, *args, **kwargs):
        ...

    def __init__(self, graph: DiGraph, node_id: str):
        self._graph = graph
        self._node_id = node_id
        assert self.attr['type'] == self.type

    @property
    def graph(self) -> DiGraph:
        return self._graph

    @property
    def node_id(self) -> Any:
        return self._node_id

    @property
    def attr(self) -> Dict[str, Any]:
        return self.graph.nodes[self.node_id]

    @property
    @abstractmethod
    def type(self) -> NodeTypes:
        ...


class BaseEdge(ABC):

    @classmethod
    @abstractmethod
    def create(cls, *args, **kwargs):
        ...

    def __init__(self, graph: DiGraph, edge_id: Tuple[str, str]):
        self._graph = graph
        self._edge_id = edge_id
        assert self.attr['type'] == self.type

    @property
    def graph(self) -> DiGraph:
        return self._graph

    @property
    def edge_id(self) -> Any:
        return self._edge_id

    @property
    def attr(self) -> Dict[str, Any]:
        return self.graph.edges[self.edge_id]

    @property
    @abstractmethod
    def type(self) -> EdgeTypes:
        ...

