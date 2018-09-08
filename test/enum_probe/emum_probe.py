import re
myfile=open('/tmp/probe.txt','r')
g_dict={}
for line in myfile.readlines():
	match=re.search(".*: (?P<edge>.*)\n",line)
	if match:
		edge=match.group('edge')
		if edge in g_dict:
			g_dict[edge]+=1
		else:
			g_dict[edge]=1
for edge1,count in g_dict.iteritems():
	print edge1+" : "+str(count)