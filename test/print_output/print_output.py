import sys
import subprocess
import os
binary = sys.argv[1]
mydir = sys.argv[2]
#list mydir
def get_file_name(rootDir):
	file_names=[]
	for lists in os.listdir(rootDir):
		path = os.path.join(rootDir, lists)
		file_names.append(path)
	return file_names
file_names=get_file_name(mydir)
os.system('rm /tmp/myoutput.txt')
myoutput = open('/tmp/myoutput.txt', 'a')
output_dict=dict()
for file1 in file_names:
	print file1
	myoutput.write('\n'+file1+'\n')
	myinput = open(file1,'r')
	p = subprocess.Popen(binary, stdin=myinput, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	out,error = p.communicate()
	myoutput.write(out)
	if out not in output_dict:
		output_dict[out]=file1
	myoutput.flush()
myoutput.close()
print 'the result!!!!!!!!!!!!'
myfile=open('/tmp/myoutput.txt','r')
for line in myfile.readlines():
	#print repr(line)
	pass
myfile.close()

for k,v in output_dict.iteritems():
	print k
	print v


