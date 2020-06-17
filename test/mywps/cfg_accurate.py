import angr
from angrutils import *
proj = angr.Project("./mywps", load_options={'auto_load_libs':False})
main = proj.loader.main_object.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.rebased_addr)
cfg = proj.analyses.CFGAccurate(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
plot_cfg(cfg, "mywps", asminst=True, remove_imports=True, remove_path_terminator=True)  