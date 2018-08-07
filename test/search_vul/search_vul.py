import requests
import sys
import json
g_result=[]
def main(search_pattern):
	global g_result
	nextpage=1
	#while(nextpage<10):
	url_str='https://api.github.com/search/code?q=strcat+language:c+repo:queueRAM/sm64tools&sort=created&order=asc'
	r = requests.get(url_str)
	d = json.loads(r.content)
	print d
	#print r.content
	'''
	d=json.loads(r.content)
	nextpage=d['nextpage']
	for result_tmp in d['results']:
		lines=''
		for k,v in result_tmp['lines'].iteritems():
			lines+=k+' '+v+'\n'
		print lines
		input_str=raw_input('y/n:')
		if input_str=='y':
			print result_tmp['repo']+result_tmp['location']+result_tmp['filename']
			g_result.append((result_tmp['repo']+result_tmp['location']+result_tmp['filename'],lines))
	'''


	
if __name__ == '__main__':
	search_pattern=sys.argv[1]
	main(search_pattern)
