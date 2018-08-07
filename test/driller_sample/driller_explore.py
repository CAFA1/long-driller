import os
import sys
import nose
import logging

import angr
import driller


l = logging.getLogger("driller.driller")



def test_vul(binary):
	
	d = driller.Driller(binary, "A"*30, "\xff"*65535, "whatever~")

	new_inputs = d.drill()
	i=0
	for tmp_input in new_inputs:
		print '\ninput '+str(i)+': '+repr(tmp_input)+'\n'
		file_tmp=open(str(i)+'.input','w')
		file_tmp.write(tmp_input[1])
		file_tmp.close()
		i=i+1


if __name__ == "__main__":
	l.setLevel('DEBUG')
	binary=sys.argv[1]
	test_vul(binary)
