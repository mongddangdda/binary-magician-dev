#
# File header here
#


from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..types import *


from abc import ABC, abstractmethod

from ..utils import ssa_var_to_str
from ..enums import NodeTypes
from ..base import BaseNode


class NoUseNode(BaseNode):
    
    def __init__(self, graph: DiGraph, node_id: str):
        super().__init__(graph, node_id)
        assert self.ssa_var

    @classmethod
    def create(cls, graph: DiGraph, ssa_var: SSAVariable, exist_ok=False, **attr):
        
        node_id = ssa_var_to_str(ssa_var)
        if graph.has_node(node_id):
            if not exist_ok:
                raise Exception # TODO: let's create exception too :)

        attr.update(type = NodeTypes.NO_USE,
                    ssa_var = ssa_var)
        graph.add_node(node_id, **attr)
        return cls(graph, node_id)

    @property
    def type(self) -> NodeTypes:
        return NodeTypes.NO_USE

    @property
    def ssa_var(self) -> SSAVariable:
        return self.attr['ssa_var']


class GraphNoUseMixin(ABC):

    @property
    @abstractmethod
    def graph(self) -> DiGraph:
        ...

    @abstractmethod
    def iter_nodes_with_type(self, node_type: NodeTypes):
        ...

    @property
    def ends_with_no_use(self):
        for node_id, attr in self.iter_nodes_with_type(NodeTypes.NO_USE):
            yield NoUseNode(self.graph, node_id)

    def add_end_with_no_use(self, ssa_var: SSAVariable, exist_ok=False, **attr):
        return NoUseNode.create(self.graph, ssa_var, exist_ok=exist_ok, **attr)

