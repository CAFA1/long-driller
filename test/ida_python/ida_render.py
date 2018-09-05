from idautils import *
from idaapi import *
from idc import *
import os
import time
import re
jnz_count=0
jnz_addr=[]
def get_all_jnz():
	global jnz_count
	global jnz_addr
	fsegmy=FirstSeg()
	segci=0
	jnz_count=0
	while(fsegmy!=BADADDR ):
		segci+=1
		mysegattr=GetSegmentAttr(fsegmy,SEGATTR_TYPE)
		if(mysegattr==2):
			segnamemy=SegName(fsegmy)
			segendmy=SegEnd(fsegmy)
			#print " (%s) is %d,segstart = %x,segend = %x" %(segnamemy,mysegattr,fsegmy,segendmy)
			addr0=fsegmy
			addr4=FindCode(addr0,SEARCH_DOWN)
			while(addr4<segendmy):
				Instruction = GetMnem(addr4)
				#str_f=GetDisasm(addr4)
				if (Instruction.find("j")!=-1 and Instruction!='jmp'):
					jnz_addr.append(addr4)
					jnz_count=jnz_count+1
				addr4=FindCode(addr4,SEARCH_DOWN)
		fsegmy=NextSeg(fsegmy)
	print 'jnz_count '+str(jnz_count) 
	return jnz_count
def get_jnz_ratio(myfile):
	global jnz_addr,jnz_count
	jnz_color_count=0
	for tmp in jnz_addr:
		if(GetColor(tmp,CIC_ITEM)!=0xffffffff):
			jnz_color_count=jnz_color_count+1
	print 'jnz_color_count '+str(jnz_color_count)+' '+str(jnz_count)+" ratio: "+str(jnz_color_count*1.0/jnz_count)
	myfile.write('jnz_color_count '+str(jnz_color_count)+' '+str(jnz_count)+" ratio: "+str(jnz_color_count*1.0/jnz_count)+'\n')

def list_trace_files():
	queue_files = os.listdir('c:\\tracefile')
	queue_files = [os.path.join('c:\\tracefile\\',q) for q in queue_files]
	return queue_files

def color_trace():
	already_render_traces=set()
	myfile=open('trace_log.txt','a+')
	
	while True:
		
		queue = list_trace_files()
		not_rendered = set(queue)-already_render_traces
		while len(not_rendered) >0:
			time.sleep(5)
			to_render_trace = list(not_rendered)[0]
			print to_render_trace
			myfile.write(to_render_trace+'\n')
			not_rendered.remove(to_render_trace)
			already_render_traces.add(to_render_trace)
			f_trace = open(to_render_trace,'r')
			for line in f_trace.readlines():
				addr_str1=re.search('Trace 0x(.*) \[(?P<addr>.*)\]',line)
				if addr_str1:
					addr_int=int(addr_str1.group('addr'),16)
					hit_count=GetColor(addr_int, CIC_ITEM)
					#print hex(addr_int),hex(hit_count+1)
					myfile.write(hex(addr_int)+' '+hex(hit_count+1)+'\n')
					SetColor(addr_int,CIC_ITEM,(hit_count+1)&0xffffffff)
			f_trace.close()
			get_jnz_ratio(myfile) 
		print 'no file now'
		time.sleep(120)
	myfile.write('end\n')
	myfile.close()

def main():	
	myfile=open('trace_log.txt','w')
	myfile.write('start\n')
	myfile.close()
	get_all_jnz()
	color_trace()
		
main()
