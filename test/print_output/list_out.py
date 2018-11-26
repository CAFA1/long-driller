#python list_out.py dir
#print the output file in the dir
#python list_out.py /dev/shm/work/control_dependency/sync/driller/queue/
import sys
import subprocess
import os
#binary = sys.argv[1]
mydir = sys.argv[1]
#list mydir
def get_file_name(rootDir):
	file_names=[]
	for lists in os.listdir(rootDir):
		path = os.path.join(rootDir, lists)
		file_names.append(path)
	return file_names
file_names=get_file_name(mydir)
#os.system('rm /tmp/myoutput.txt')
#myoutput = open('/tmp/myoutput.txt', 'a')
output_dict=dict()
for file1 in file_names:
	#print file1
	try:
		myinput = open(file1,'r')
		content=myinput.read()
		if content not in output_dict:
			output_dict[content]=file1
	except:
		pass

print 'the result!!!!!!!!!!!!'
i=0
for k,v in output_dict.iteritems():
	i=i+1
	print '\n\n'+str(i)
	print repr(k)
	print repr(v)


