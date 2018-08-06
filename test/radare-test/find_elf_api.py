import os
import subprocess
import r2pipe
import sys
import re
import json
g_func_name_addr_dict={} #func_name  func_addr_int

def get_file_name_strings(file_dir,api):
	string_interesting=api
	file_elf=[]
	i=0
	for root,dirs,files in os.walk(file_dir):
		for file in files:
			this_file=os.path.join(root,file)
			out_bytes=subprocess.check_output(['file',os.path.join(root,file)])
			
			if(out_bytes.find('ELF')!=-1 and out_bytes.find('LSB relocatable')==-1):
				try:
					out_bytes1=subprocess.check_output('strings '+os.path.join(root,file)+' |grep  '+string_interesting,shell=True)
					#print 'string output:\n '+out_bytes1
					if(out_bytes1!=''):
						
						print 'find file : '+this_file+' !!!!!!' + ' '+str(i)
						file_elf.append(this_file)
						i=i+1
				except:
					pass
	return file_elf
'''
[0x00400570]> axt @ sym.imp.strcpy
sym.mystrcpy 0x400684 [CALL] call sym.imp.strcpy
main 0x4006dd [CALL] call sym.imp.strcpy
'''
#return the file name which has the func
def get_func_elf(file_name_list,func_name):
	global g_func_name_addr_dict
	file_elf_func=set()
	for file_tmp in file_name_list:
		r2 = r2pipe.open(file_tmp)
		#axt find reference
		func_json = r2.cmd("aaa;aflj ")
		func_list = json.loads(func_json)
		#
		for func_dict in func_list:
			offset_int=func_dict['offset']
			g_func_name_addr_dict[func_dict['name']]=offset_int
			if func_dict['name']=='sym.imp.'+func_name:
				file_elf_func.add(file_tmp)
				break
	return file_elf_func




if __name__ == '__main__':
	if(len(sys.argv)!=3 ):
		print "python .py dir api"
		exit()
	dir1= sys.argv[1]
	api=sys.argv[2]
	files_name=get_file_name_strings(dir1,api)
	files_name_set=get_func_elf(files_name,api)
	for elf in files_name_set:
		cmd='python elf_analysis.py '+elf+' strcpy'
		os.system(cmd)

	print 'ok'