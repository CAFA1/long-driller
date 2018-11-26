# -*- coding: UTF-8 -*-
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import sys
import re
import matplotlib as mpl
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

custom_font = mpl.font_manager.FontProperties(fname=u'微软雅黑.ttf')

plot_file_origin=open('driller_sample_origin/fuzzer-master.log','r')
plot_file_probe=open('driller_sample_probe/fuzzer-master.log','r')
time_list_origin=[]
trans_list_origin=[]
for line in plot_file_origin.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list_origin.append(time)
		trans_list_origin.append(trans)
time_list_probe=[]
trans_list_probe=[]
for line in plot_file_probe.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list_probe.append(time)
		trans_list_probe.append(trans)


plt.title('')
plt.plot(time_list_probe, trans_list_probe, color='green', label='ForwardProbe')
plt.plot(time_list_origin, trans_list_origin, color='red', linestyle='--',label='DrillerCore')
#plt.plot(sub_axix, test_acys, color='red', label='testing accuracy')
#plt.plot(x_axix, train_pn_dis,  color='skyblue', label='PN distance')
plt.legend(loc=2) 
plt.xlabel(u'时间（秒）',fontproperties=custom_font)
plt.ylabel(u'状态转移数',fontproperties=custom_font)
plt.savefig('driller_sample.png')
plt.show()
