import os
import subprocess
import r2pipe
import sys
import re
import json
import angr
g_func_name_addr_dict={} #func_name  func_addr_int
g_caller_func_name_addr_set=set() #caller_func_name,func_addr_int,func_call_instruction_addr
'''
[0x00400570]> axt @ sym.imp.strcpy
sym.mystrcpy 0x400684 [CALL] call sym.imp.strcpy
main 0x4006dd [CALL] call sym.imp.strcpy
'''
#return the file name which has the func
def analyze_elf(elf,api):
	global g_func_name_addr_dict,g_caller_func_name_addr_set
	r2 = r2pipe.open(elf)
	#afl find all funcs
	func_json = r2.cmd("aaa;aflj ")
	func_list = json.loads(func_json)
	flag_find_api=False
	for func_dict in func_list:
		offset_int=func_dict['offset']
		g_func_name_addr_dict[func_dict['name']]=offset_int
		if func_dict['name']=='sym.imp.'+api:
			flag_find_api=True
	if flag_find_api==False:
		print 'warning: no api find'
		return
	
	#axt find reference func
	func_json = r2.cmd("axtj @ sym.imp."+api)

	func_list = json.loads(func_json)
	for func_dict in func_list:
		#func_caller_name=func_dict['fcn_name']
		func_caller_func_addr=func_dict['fcn_addr'] #angr begin addr
		func_caller_call_instruction_addr=func_dict['from'] # angr to addr
		g_caller_func_name_addr_set.add((func_caller_func_addr,func_caller_call_instruction_addr))
	print g_caller_func_name_addr_set

def angr_analyze_func(elf,api):
	proj = angr.Project(elf, load_options={"auto_load_libs": True})
	for caller_func_name_addr in g_caller_func_name_addr_set:
		FIND_ADDR = caller_func_name_addr[1] 
		func_start_addr = caller_func_name_addr[0]
		print 'info: analyze from '+hex(func_start_addr)+' to '+hex(FIND_ADDR)
		
		start_state = proj.factory.blank_state(addr=func_start_addr)
		
		sm = proj.factory.simulation_manager(start_state)
		sm.explore(find=FIND_ADDR) #, avoid=AVOID_ADDR)
		found = sm.found[0]
		#load parameters
		rdi = found.regs.rdi
		rsi = found.regs.rsi
		FAKE_ADDR = 0x100000
		strlen = lambda state, arguments: angr.SIM_PROCEDURES['libc']['strlen'](proj, FAKE_ADDR, proj.arch).execute(state, arguments=arguments)
		flag_length_dest = strlen(found, arguments=[rdi]).ret_expr
		flag_length_src = strlen(found, arguments=[rsi]).ret_expr
		print flag_length_dest
		print flag_length_src

		flag_length_dest_int = min(found.solver.eval_upto(flag_length_dest, 3))
		flag_length_src_int = min(found.solver.eval_upto(flag_length_src, 3))
		print hex(flag_length_dest_int),hex(flag_length_src_int)

if __name__ == '__main__':
	if(len(sys.argv)!=3 ):
		print "python .py elf api"
		exit()
	elf= sys.argv[1]
	api=sys.argv[2]
	analyze_elf(elf,api)
	angr_analyze_func(elf,api)
	print 'ok'