from binaryninja import BinaryView, Function, Variable, log_warn
from binaryninja.mediumlevelil import MediumLevelILOperation


class FunctionTagger:

    def __init__(self, bv: BinaryView):
        self.bv = bv

    def tag_by_call_with_string_parameter(self, callee: Function, parameter_index: int):
        
        tagged = {}

        for ref in self.bv.get_code_refs(callee.start):
            
            if not ref.mlil:
                log_warn(f"0x{ref.address:x} is not lifted.")
                continue

            if ref.mlil.operation not in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_CALL_OUTPUT,
                                          MediumLevelILOperation.MLIL_CALL_PARAM, MediumLevelILOperation.MLIL_CALL_UNTYPED,
                                          MediumLevelILOperation.MLIL_TAILCALL, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED]:
                log_warn(f"0x{ref.address:x} is invalid call site.")
                continue

            if len(ref.mlil.params) < parameter_index + 1:
                log_warn(f"0x{ref.address:x} is invalid call (parameters)")
                continue

            if type(ref.mlil.params[parameter_index]) == Variable:
                log_warn(f"0x{ref.address:x} call site has variable parameter at index {parameter_index}")
                continue

            if ref.mlil.params[parameter_index].operation != MediumLevelILOperation.MLIL_CONST_PTR:
                log_warn(f"0x{ref.address:x} call {parameter_index}'th parameter is not a MLIL_CONST_PTR")
                continue

            category_string = self.bv.get_string_at(ref.mlil.params[parameter_index].constant)
            if not category_string:
                log_warn(f"0x{ref.address:x} failed to get string at 0x{ref.mlil.params[parameter_index].constant:x}")
                continue

            if category_string.value not in tagged:
                tagged[category_string.value] = [ref.function.start]
                continue

            if ref.function.start not in tagged[category_string.value]:
                tagged[category_string.value].append(ref.function.start)
                continue

        return tagged

