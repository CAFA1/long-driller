from bs4 import BeautifulSoup
import requests
import re
cookie_my="lang=zh_cn;" \
          " __utmc=201260338;" \
          " __utmz=201260338.1534395903.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided);" \
          " _cmpQcif3pcsupported=1;" \
          " cb813690bb90b0461edd205fc53b6b1c=713f8196405a9a33273bbf15141a3cb53013b13ea%3A4%3A%7Bi%3A0%3Bs%3A26%3A%22longlong12341234%40gmail.com%22%3Bi%3A1%3Bs%3A26%3A%22longlong12341234%40gmail.com%22%3Bi%3A2%3Bi%3A2592000%3Bi%3A3%3Ba%3A3%3A%7Bs%3A2%3A%22id%22%3Bs%3A5%3A%2216422%22%3Bs%3A4%3A%22name%22%3Bs%3A12%3A%22Xiaolong+Liu%22%3Bs%3A4%3A%22type%22%3Bs%3A1%3A%22n%22%3B%7D%7D; " \
          "__qca=P0-867414501-1534396120749; " \
          "PHPSESSID=1fa6c59ad12d4b1faf749b998683e5b1;" \
          " __utma=201260338.147764455.1534395903.1534395903.1534400528.2; " \
          "__utmb=201260338.3.10.1534400528"
session = requests.session()
session.cookies.set('lang','en_us')
session.cookies.set('__utmc','201260338')
session.cookies.set('__utmz','201260338.1534395903.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided)')
session.cookies.set('_cmpQcif3pcsupported','1')
session.cookies.set('cb813690bb90b0461edd205fc53b6b1c','713f8196405a9a33273bbf15141a3cb53013b13ea%3A4%3A%7Bi%3A0%3Bs%3A26%3A%22longlong12341234%40gmail.com%22%3Bi%3A1%3Bs%3A26%3A%22longlong12341234%40gmail.com%22%3Bi%3A2%3Bi%3A2592000%3Bi%3A3%3Ba%3A3%3A%7Bs%3A2%3A%22id%22%3Bs%3A5%3A%2216422%22%3Bs%3A4%3A%22name%22%3Bs%3A12%3A%22Xiaolong+Liu%22%3Bs%3A4%3A%22type%22%3Bs%3A1%3A%22n%22%3B%7D%7D')
session.cookies.set('PHPSESSID','1fa6c59ad12d4b1faf749b998683e5b1')
session.cookies.set('__qca','P0-867414501-1534396120749')

session.cookies.set('__utma','201260338.147764455.1534395903.1534395903.1534400528.2')
session.cookies.set('__utmb','201260338.3.10.1534400528')

html = session.get("https://www.myhuiban.com/conferences?lang=en_us")
content=html.text
soup = BeautifulSoup(content, features='lxml')
table=soup.find_all('table')[0]
data_list=[]
for idx, tr in enumerate(table.find_all('tr')):
    if idx != 0:
        print str(idx)
        tds = tr.find_all('td')
        location = tds[9].contents[0]
        years=''
        kong=0
        years1 = ''
        try:
            years1 = tds[10].contents[0]
        except:
            kong=1
        if kong==1:
            continue
        #<span class="badge badge-info">4</span>
        years2 = re.search('\>(?P<num>.*)\<',repr(years1))
        if years2:
            years=years2.group('num')
        if (location.find('China') != -1 and years!=''):
            data_list.append({
                'full_name': tds[4].contents[0],
                'submission': tds[6].contents[0],
                'conference': tds[8].contents[0],
                'location': tds[9].contents[0],
                'years':years
            })
for page in range(2,254):
    url='https://www.myhuiban.com/conferences?Conference_page='+str(page)+'&ajax=yw2'
    html = session.get(url)
    content = html.text
    soup = BeautifulSoup(content, features='lxml')
    table = soup.find_all('table')[0]

    for idx, tr in enumerate(table.find_all('tr')):
        if idx != 0:
            print str(page)
            tds = tr.find_all('td')
            location=tds[9].contents[0]
            submission = tds[6].contents[0]
            conference =tds[8].contents[0]
            years = ''
            years1=''
            kong = 0
            try:
                years1 = tds[10].contents[0]
            except:
                kong = 1
            if kong == 1:
                continue
            # <span class="badge badge-info">4</span>
            years2 = re.search('\>(?P<num>.*)\<', repr(years1))
            if years2:
                years = years2.group('num')
            if(location.find('China')!=-1  and years!='' and submission.find('2018')!=-1 and conference.find('2018')!=-1):

                data_list.append({
                    'full_name': tds[4].contents[0],
                    'submission': tds[6].contents[0],
                    'conference': tds[8].contents[0],
                    'location': tds[9].contents[0],
                    'years': years
                })
file_result=open('result.txt','w')
for item in data_list:
    file_result.write(repr(item)+'\n')
file_result.close()
#https://www.myhuiban.com/conferences?Conference_page=2&ajax=yw2
#https://www.myhuiban.com/conferences?Conference_page=4&ajax=yw2