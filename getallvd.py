import os
import sys
import lib_rule
import lib_pickle
import lib_TheardPool
import threading
import httplib2

try:
    from bs4 import *
except Exception:
    from BeautifulSoup import *

cvedt={}
cnvdlt=[]
http=httplib2.Http()


def getvid4cnvd(pool,cnvd):
    print cnvd,
    cve,bid=lib_rule.getdesc4cnvd(cnvd,vid=True)
    if cve:
        if cve=='NULL':
            cnvdlt.append((cnvd,bid))
        else:
            if bid=='NULL':
                bid=lib_rule.getdesc4cve(cve)[0]
            cvedt[cve]=(cnvd,bid)
    else:
        print "Error:",cnvd

def geturl(year,total,current):
    if total==0 or current<total:
        url="http://www.cnvd.org.cn/flaw/listResult?baseinfoBeanbeginTime=%d-01-01&max=100&baseinfoBeanFlag=0&manufacturerId=-1&condition=1&keyword=&categoryId=-1&keywordFlag=0&refenceInfo=&threadIdStr=&cnvdId=&causeIdStr=&field=openTime&referenceScope=-1&cnvdIdFlag=0&serverityIdStr=&order=asc&baseinfoBeanendTime=%d-12-31&editionId=-1&offset=%d" %(year,year,current)
        return url


def getcnvd4year(year):
    pool=lib_TheardPool.threadpool(tmax,invrt=ivt,start=False)
    current=0
    total=0
    while True:
        url=geturl(year,total,current)
        if not url:
            break
        body=lib_rule.opencnvdurl(http,url)
        if body:
                soup=BeautifulSoup(body)
                if not total:total=int(soup.div('span')[-1].contents[0][2:-2])
                soups=soup.tbody('tr')
                for soup in soups:
                    try:
                        #title=soup.td.a['title']
                        cnvd=soup.td.a['href'][16:]
                        #print cnvd,
                        pool.addtask(getvid4cnvd,(pool,cnvd))
                    except Exception:
                        print "Exception",soup
        else:
            print "Error:",url
        current+=100
    print '\n================='
    pool.start()
    pool.waitPoolComplete()
    
def getallcnvd():
    for i in range(2002,2004):
        print "Get %d cnvd from internet now...." %i
        getcnvd4year(i)

try:  
    tmax=int(sys.argv[1])
    ivt=float(sys.argv[2])
except Exception:
    tmax=50
    ivt=1

getallcnvd()
#lib_pickle.dump2file('F:\\CVEVD\\cvedt.pkl',cvedt)
#lib_pickle.dump2file('F:\\CVEVD\\cnvdlt.pkl',cnvdlt)
lib_pickle.dict2txt('/home/forst/cvedt.txt',cvedt)
lib_pickle.list2txt('/home/forst/cnvdlt.txt',cnvdlt)
print "\nNumber:",len(cvedt),len(cnvdlt)