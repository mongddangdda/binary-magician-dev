from binaryninja import *
from typing import *

visitor_class_template = """
class MediumLevelILVisitor:
"""

visitor_method_template = """
    def visit_{op}(self, expr: {cls}, *args, **kwargs):
        return self.visit_Default(expr, *args, **kwargs)
"""

visitor_match_template = """
    def visit(self, expr: MediumLevelILInstruction, *args, **kwargs):
        match expr.operation:
"""

visitor_case_template = """            case MediumLevelILOperation.{op}:
                return self.visit_{op}(expr, *args, **kwargs)\n"""

def map_enum_with_class(bv: BinaryView):
    mapped={}
    func = bv.functions[0].mlil
    for op in MediumLevelILOperation:
        index = func.append(func.expr(op))
        assert func[index].operation == op
        mapped[op.name] = type(func[index])
    return mapped

def is_ssa_instruction(instr: MediumLevelILInstruction):
    return issubclass(instr, SSA)

def main(args):
    
    with open_view(args.tmp_bin) as bv:
        
        mapped = map_enum_with_class(bv)
        
        head = visitor_class_template
        body = ''
        tail = visitor_match_template

        for op in mapped:
            
            cls = mapped[op]

            if args.print == "python" or args.print == "python_all":
                if not is_ssa_instruction(cls):
                    body += visitor_method_template.format(op=op, cls=cls.__name__)
                    tail += visitor_case_template.format(op=op)
            if args.print == "python_ssa" or args.print == "python_all":                    
                if is_ssa_instruction(cls):
                    body += visitor_method_template.format(op=op, cls=cls.__name__)
                    tail += visitor_case_template.format(op=op)

        print(head + body + tail)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--tmp-bin", required=True)
    parser.add_argument("-p", "--print", choices=["python", "python_ssa", "python_all"], default="python_all")
    args = parser.parse_args()
    main(args)