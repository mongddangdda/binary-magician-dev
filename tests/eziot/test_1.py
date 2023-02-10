from binaryninja import open_view

from .importer import tests
from bmag.def_use.mlil_ssa_fwd import MLILSsaFwdInstTracer, VisitSite
from bmag.def_use.graph import Graph as DefUseGraph

with open_view(tests / 'eziot' / 'bin' / 'eziot-service.bndb') as bv:

    func = bv.get_functions_containing(0x1ff0)[0]
    inst = func.mlil.ssa_form[80]
    ssa_var = inst.dest

    tracer = MLILSsaFwdInstTracer(func)
    tracer.set_graph(DefUseGraph())

    for use in func.mlil.ssa_form.get_ssa_var_uses(ssa_var):
        tracer.add_site_to_visit(VisitSite(use, ssa_var))

    try:
        tracer.trace()
    finally:
        tracer.graph.export_html("/Users/dhkim/Downloads/result.html")
