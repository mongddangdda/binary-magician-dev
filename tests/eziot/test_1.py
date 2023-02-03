from binaryninja import open_view

import importer
from bmag.def_use.mlil_ssa_fwd.inst_visitor import FwdInstTracer

with open_view(importer.tests / 'eziot' / 'bin' / 'eziot-service.bndb') as bv:

    func = bv.get_functions_containing(0x1ff0)[0]
    inst = func.mlil.ssa_form[80]
    ssa_var = inst.dest

    tracer = FwdInstTracer(func)
    tracer.trace(src_ssa_var=ssa_var)

    tracer.def_use_graph.export_html("/Users/dhkim/Downloads/result.html")
