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

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Driller explore interface")
	parser.add_argument('binary', help="the path to the target binary to fuzz")


	parser.add_argument('-w', '--work-dir', help="The work directory for AFL.", default="/dev/shm/work/")

	parser.add_argument('-C', '--first-crash', help="Stop on the first crash.", action='store_true', default=False)

	parser.add_argument('--run-timeout', help="Number of seconds permitted for each run of binary", type=int)
	parser.add_argument('--driller-timeout', help="Number of seconds to allow driller to run", type=int, default=10*60)
	parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
	args = parser.parse_args()


	try: os.mkdir("/dev/shm/work/")
	except OSError: pass

	drill_extension = None
	grease_extension= None

	print "[*] Drilling..."
	drill_extension = driller.LocalCallback(num_workers=1, worker_timeout=args.driller_timeout, length_extension=args.length_extension)
	stuck_callback = (
		(lambda f: (grease_extension(f), drill_extension(f))) if drill_extension and grease_extension
		else drill_extension or grease_extension
	)
	fuzzer = fuzzer.Fuzzer(
		args.binary, args.work_dir, 
		create_dictionary=0, stuck_callback=stuck_callback
	)
	fuzzer.call_stuck_callback()
