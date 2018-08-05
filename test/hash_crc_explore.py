#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

FIND_ADDR = 0x00400813 # This is right after the printf for the OK password.
#AVOID_ADDR = 0x4006DD # mov dword [esp], str.Invalid_Password__n ; [0x804854f:4]=0x61766e49 LEA str.Invalid_Password__n ; "Invalid Password!." @ 0x804854f

def main():
	proj = angr.Project('./hash_crc', load_options={"auto_load_libs": True})

	sm = proj.factory.simulation_manager()
	sm.explore(find=FIND_ADDR) #, avoid=AVOID_ADDR)
	#return 'done'
	return sm.found[0].posix.dumps(0).lstrip('+0').rstrip('B\n')


if __name__ == '__main__':
	print(repr(main()))


