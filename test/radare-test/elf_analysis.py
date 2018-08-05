import os
import subprocess
import r2pipe
import sys
import re
import json
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
	file_elf_func=[]
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
		func_caller_name=func_dict['fcn_name']
		func_caller_func_addr=func_dict['fcn_addr'] #angr begin addr
		func_caller_call_instruction_addr=func_dict['from'] # angr to addr
		g_caller_func_name_addr_set.add((func_caller_name,func_caller_func_addr,func_caller_call_instruction_addr))
	print g_caller_func_name_addr_set


	'''
	#print read_str
	if(read_str!=''):
		afl_str = r2.cmd('axt @ sym.imp.'+func_name)
		afl_list=afl_str.split('\n')
		for afl_func_tmp in afl_list:
			func_name_tmp=afl_func_tmp.split(' ')[0]
			call_func_addr=afl_func_tmp.split(' ')[1]
			print afl_list
		#print afl_str
		file_elf_func.append(file_tmp)
		#print file_tmp
	'''
	return file_elf_func




if __name__ == '__main__':
	if(len(sys.argv)!=3 ):
		print "python .py elf api"
		exit()
	elf= sys.argv[1]
	api=sys.argv[2]
	analyze_elf(elf,api)

	print 'ok'