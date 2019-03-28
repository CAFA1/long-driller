#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import angr
import os
import sys
import claripy
#python bbl_sample.py program bbl_addr taint_mode
#python bbl_sample.py /home/l/Downloads/coreutils-8.30/src/basename 0x4013C7
#python bbl_sample.py ../mywps/mywps 0x4007d5
#python bbl_sample.py /home/l/Downloads/file-5.35/src/.libs/file 0x402000
program = sys.argv[1]
FIND_ADDR = int(sys.argv[2],16)

def explore_agrv():
	proj = angr.Project(program)
	sym_arg_size = 40   #max number of bytes we'll try to solve for
	sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
	argv = [proj.filename] 
	argv.append(sym_arg)
	state = proj.factory.entry_state(args=argv)
	sm = proj.factory.simulation_manager(state)
	sm.explore(find=FIND_ADDR) 
	found = sm.found
	if len(found) > 0:  
		found = sm.found[0]
		result = found.solver.eval(argv[1], cast_to=bytes)
		try:
			result = result[:result.index(b'\0')]
		except ValueError:
			pass
	else: 
		result = "Couldn't find any paths which satisfied our conditions."
	return result
def explore_file():
	proj = angr.Project(program,load_options={'auto_load_libs': True})
	argv = [proj.filename,'test.txt']
	state = proj.factory.entry_state(args=argv)
	file_name = "test.txt"
	bytestring = state.solver.BVS('content', 64*8)
	license_file = angr.storage.file.SimFile(file_name, bytestring)
	state.fs.insert(file_name, license_file)
	sm = proj.factory.simulation_manager(state)
	sm.explore(find=FIND_ADDR) 
	found = sm.found
	if len(found) > 0:  
		found = sm.found[0]
		result = found.solver.eval(bytestring, cast_to=bytes)
		try:
			result = result[:result.index(b'\0')]
		except ValueError:
			pass
	else: 
		result = "Couldn't find any paths which satisfied our conditions."
	return result

if __name__ == '__main__':
	print(repr(explore_file()))


