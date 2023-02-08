from binaryninja import open_view

import importer
from bmag.def_use.mlil_ssa_fwd.inst_tracer import FwdInstTracer, VisitSite

with open_view(importer.tests / 'eziot' / 'bin' / 'eziot-service.bndb') as bv:

    func = bv.get_functions_containing(0x1ff0)[0]
    inst = func.mlil.ssa_form[80]
    ssa_var = inst.dest

    tracer = FwdInstTracer(func)
    for use in func.mlil.ssa_form.get_ssa_var_uses(inst.dest):
        tracer.add_site_to_visit(VisitSite(use, ssa_var))

    tracer.trace()

    tracer.def_use_graph.export_html("/Users/dhkim/Downloads/result.html")
