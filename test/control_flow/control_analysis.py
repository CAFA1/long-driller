import angr
def solve(s):
	p = angr.Project("./control_dependency",auto_load_libs=False)
	cfg = p.analyses.CFG(show_progressbar=True)

	#list all funcs(dict)
	for key,func in cfg.functions.iteritems():
		#get func caller
		callers = cfg.functions.callgraph.predecessors(func.addr)
		caller_funcs = [ cfg.functions[caller_addr] for caller_addr in callers ]
		print func.name
		print caller_funcs
		print len(caller_funcs)
		'''
		caller_func = sorted(caller_funcs, key=lambda f: f.size)[-1]
		blocks = sorted(func.blocks, key=lambda b: b.addr)
		insns1=blocks[-1].capstone.insns
		insns2=blocks[-2].capstone.insns
		print insns1
		print insns2
		insns = [ insn for insn in block.capstone.insns if insn.mnemonic == 'cmp' and insn.operands[0].type == 1 and insn.operands[0].reg in (2, 10) ]
		if not insns:
			continue
		insn = insns[0]
		imm = insn.operands[1].imm
		s += chr(imm)
		'''
	return s

s=''
print solve(s)