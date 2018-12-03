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

plot_file_probe_1=open('driller_sample_probe_1/fuzzer-master.log','r')
plot_file_probe_2=open('driller_sample_probe_2/fuzzer-master.log','r')
plot_file_probe_3=open('driller_sample_probe_3/fuzzer-master.log','r')
plot_file_probe_4=open('driller_sample_probe_4/fuzzer-master.log','r')
#DrillerCore
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
#probe when N=4
time_list_probe_4=[]
trans_list_probe_4=[]
for line in plot_file_probe_4.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list_probe_4.append(time)
		trans_list_probe_4.append(trans)

#probe when N=1
time_list_probe_1=[]
trans_list_probe_1=[]
for line in plot_file_probe_1.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list_probe_1.append(time)
		trans_list_probe_1.append(trans)

#probe when N=2
time_list_probe_2=[]
trans_list_probe_2=[]
for line in plot_file_probe_2.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list_probe_2.append(time)
		trans_list_probe_2.append(trans)

#probe when N=2
time_list_probe_3=[]
trans_list_probe_3=[]
for line in plot_file_probe_3.readlines():
	match=re.search(".*0m(?P<days>.*) days, (?P<hours>.*) hrs, (?P<mins>.*) min, (?P<secs>.*) sec,.*total, (?P<trans>.*) transitions,",line)
	if match:
		days=int(match.group('days'),10)
		hours=int(match.group('hours'),10)
		mins=int(match.group('mins'),10)
		secs=int(match.group('secs'),10)
		trans=int(match.group('trans'),10)
		time=secs+mins*60+hours*60*60
		time_list_probe_3.append(time)
		trans_list_probe_3.append(trans)

plt.title('')

plt.plot(time_list_probe_1, trans_list_probe_1, color='blue', linestyle='-.',label='FB-SA(N=1)')
plt.plot(time_list_probe_2, trans_list_probe_2, color='fuchsia', linestyle=':',label='FB-SA(N=2)')
plt.plot(time_list_probe_3, trans_list_probe_3, color='indigo', linestyle='--',label='FB-SA(N=3)')
plt.plot(time_list_probe_4, trans_list_probe_4, color='green', linestyle='-',label='FB-SA(N=4)')
plt.plot(time_list_origin, trans_list_origin, color='red', linestyle='--',label='DrillerCore') #

plt.annotate('N=3',xy=(348.3,60),xytext=(190.3,60.3),arrowprops=dict(facecolor='indigo', shrink=0.05))
plot_file_origin.close()
plot_file_probe_1.close()
plot_file_probe_2.close()
plot_file_probe_3.close()
plot_file_probe_4.close()
#set front size
plt.legend(loc=2,prop={'size':12}) 
plt.xlabel(u'时间（秒）',fontproperties=custom_font)
plt.ylabel(u'状态转移数',fontproperties=custom_font)
plt.savefig('driller_sample.png')
plt.show()
