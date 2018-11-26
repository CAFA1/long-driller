# -*- coding: UTF-8 -*-
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import sys
import re
plot_file1=open(sys.argv[1],'r')
time_list=[]
trans_list=[]
for line in plot_file1.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list.append(time)
		trans_list.append(trans)


plt.title('Coverage Graph')
plt.plot(time_list, trans_list, color='green', label='Coverage Graph')
#plt.plot(sub_axix, test_acys, color='red', label='testing accuracy')
#plt.plot(x_axix, train_pn_dis,  color='skyblue', label='PN distance')
plt.legend() 
plt.xlabel('Time(s)')
plt.ylabel('Transitions')
plt.show()
