#driller offline 
#!/usr/bin/env python

import os
import sys
import imp
import time
import fuzzer
import shutil
import socket
import driller
import tarfile
import argparse
import importlib
import logging.config
import multiprocessing
import time
if __name__ == "__main__":
	#long cmd: python driller_explore.py -d 1 data_flow
	parser = argparse.ArgumentParser(description="Driller explore interface")
	parser.add_argument('binary', help="the path to the target binary to fuzz")

	parser.add_argument('-C', '--first-crash', help="Stop on the first crash.", action='store_true', default=False)

	parser.add_argument('--run-timeout', help="Number of seconds permitted for each run of binary", type=int)
	parser.add_argument('--driller-timeout', help="Number of seconds to allow driller to run", type=int, default=10*60)
	parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
	parser.add_argument('-d', '--driller_workers', help="When the fuzzer gets stuck, drill with N workers.", type=int)
	
	args = parser.parse_args()


	try: os.system("mkdir -p /dev/shm/work/"+os.path.basename(args.binary)+'/driller/queue')
	except:
		pass

	queue_dir="/dev/shm/work/"+os.path.basename(args.binary)+'/driller/queue/'
	os.system("echo fuzz > "+queue_dir+'id:0')
	bitmap=open(queue_dir+'bitmap','w')
	bitmap.write("\xff"*65535)
	bitmap.close()

	queue = filter(lambda x: x != "bitmap" and x!='driller', os.listdir(queue_dir))
	#print queue
	already_drilled_inputs=set()
	num_workers = args.driller_workers
	running_workers=[]
	#drill_extension = driller.LocalCallback(num_workers, worker_timeout=args.driller_timeout, length_extension=args.length_extension)
	while len(queue):
		time.sleep(2)
		queue = filter(lambda x: x != "bitmap" and x!='driller', os.listdir(queue_dir))
		not_drilled = set(queue) - already_drilled_inputs
		#print not_drilled
		if len(not_drilled) == 0:
			print "n",
		running_workers = [x for x in running_workers if x.is_alive()]
		while len(running_workers) < num_workers and len(not_drilled) > 0:
			#print '3'
			time.sleep(2)
			running_workers = [x for x in running_workers if x.is_alive()]
			to_drill_path = list(not_drilled)[0]
			not_drilled.remove(to_drill_path)
			already_drilled_inputs.add(to_drill_path)
			print to_drill_path
			proc = multiprocessing.Process(target=driller.local_callback._run_drill_long, args=(args.binary,args.driller_timeout, queue_dir, queue_dir+ to_drill_path),
					kwargs={'length_extension': args.length_extension})
			proc.start()
			running_workers.append(proc)
	
