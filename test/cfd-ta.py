
CTCF-BR=set()
trace = QEMURunner(b, s) 
s1=full_init_state()
preconstrain_file(s, stdin) 

while bb_cnt < len(trace):
	step to a branch state s2 {state|state has two successor states}
	select the successor state s3 {state| state is not in the trace}
	remove_preconstraints() 





	if 'diverted' not in simgr.stashes: #liu in step(31.4) function find the 'diverted' state
		continue
	#http://angr.io/api-doc/angr.html
	while simgr.diverted:
		state = simgr.diverted.pop(0)
		l.debug("Found a diverted state, exploring to some extent.")
		w = self._writeout(state.history.bbl_addrs[-1], state) #liu solve the state and generate a new sample
		if w is not None:
			yield w
		for i in self._symbolic_explorer_stub(state):
			yield i