import angr
from angrutils import *
# # load your project
p = angr.Project('./mywps', load_options={'auto_load_libs': False})
# # Generate a static CFG
cfg = p.analyses.CFGFast()
print("This is the graph:", cfg.graph)
print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

entry_node = cfg.get_any_node(p.entry)
print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(p.entry)))

print("Predecessors of the entry point:", entry_node.predecessors)
print("Successors of the entry point:", entry_node.successors)
print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + hex(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])

# generate png
plot_cfg(cfg, "mywps", asminst=True, remove_imports=True, remove_path_terminator=True)  