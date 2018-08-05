#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import angr
import os
os.environ['LD_LIBRARY_PATH'] = os.getcwd()
# 0x0040081f      bfdc084000     mov edi, str.match_2        ; testso.c:22    printf("match 2\n"); ; 0x4008dc ; "match 2" ; const char *s
FIND_ADDR = 0x0040081f 
def main():
	proj = angr.Project('./testso', load_options={"auto_load_libs": True})
	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR) #, avoid=AVOID_ADDR)
	return sm.found[0].posix.dumps(0).lstrip('+0').rstrip('B\n')
if __name__ == '__main__':
	print(repr(main()))


