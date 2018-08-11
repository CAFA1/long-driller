#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import angr
import os
# os.environ['LD_LIBRARY_PATH'] = os.getcwd()

FIND_ADDR = 0x004006c0#0x004006eb 
def main():
	proj = angr.Project('./data_flow', load_options={"auto_load_libs": False})
	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR) #, avoid=AVOID_ADDR)
	return sm.found[0].posix.dumps(0).lstrip('+0').rstrip('B\n')
if __name__ == '__main__':
	print(repr(main()))


