import os
import sys
import lib_rule
import lib_pickle
import lib_TheardPool
import threading
import httplib2
import re

try:
    from bs4 import *
except Exception:
    from BeautifulSoup import *


cnvdlist=[]
cvelist=[]
http=httplib2.Http()
pos=lib_rule.getostype()
def getvid4cnvd(pool,cnvd):#,http):
    #print cnvd,
    edesc=''
    ename=''
    try:
        cve,bid,cname,cdesc=lib_rule.getdesc4cnvd(cnvd,code='gbk',vid=True)#,rhttp=http)
        if cve:
            c_bid,edesc=lib_rule.getdesc4cve(cve)#,rhttp=http)
            if bid=='NULL':bid=c_bid
            if bid:
                ename=lib_rule.getdesc4bid(bid)[0]
                if ename:ename=ename.encode('gbk')
        cnvdlist.append((cve,bid,cnvd,cname,cdesc,ename,edesc))
        print cnvd,
    except Exception:
        print "\nError: %s" %cnvd

def geturl(year,total,current):
    if total==0 or current<total:
        url="http://www.cnvd.org.cn/flaw/listResult?baseinfoBeanbeginTime=%d-01-01&max=100&baseinfoBeanFlag=0&manufacturerId=-1&condition=1&keyword=&categoryId=-1&keywordFlag=0&refenceInfo=&threadIdStr=&cnvdId=&causeIdStr=&field=openTime&referenceScope=-1&cnvdIdFlag=0&serverityIdStr=&order=asc&baseinfoBeanendTime=%d-12-31&editionId=-1&offset=%d" %(year,year,current)
        return url


def getcnvd4year(year):
    pool=lib_TheardPool.threadpool(tmax,invrt=ivt,start=False)#,ishttp=True,tasks=200)
    current=0
    total=0
    while True:
        url=geturl(year,total,current)
        if not url:
            break
        body=lib_rule.opencnvdurl(http,url)
        if body:
                soup=BeautifulSoup(body)
                if not total:total=int(soup.div('span')[-1].contents[0].replace('&nbsp;',' ')[2:-2])
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
    print "Get all cnvd from net......."
    global cnvdlist
    for i in range(start,end):
        print "Get %d cnvd from internet now...." %i
        getcnvd4year(i)
        if pos==1:
            lib_pickle.dump2file(os.getcwd()+'/cnvd_%d.pkl' %i,cnvdlist)
        else:
            lib_pickle.dump2file('F:\\CVEVD\\cnvd_%d.pkl'%i,cnvdlist)
        print "\n %d Number:" %i,len(cnvdlist)
        cnvdlist=[]


def getcnvdlist():
    print "Get cnvdlist from pkl......"
    cnvdlist=[]
    for i in range(2002,2016):
        year=lib_pickle.get4file('F:\\CVEVD\\cnvd_%d.pkl' %i)
        cnvdlist.extend(year)
    return cnvdlist


#==========================

def getbid4str(line):
    i=line.find("www.securityfocus.com/bid/")
    if i>0:
        j=line.find('"',i)
        return line[i+26:j]

def parsenode(nodes):
    rs=[None,None,None]
    i=nodes[0].find('id=',0,20)
    rs[0]=nodes[0][i+8:i+17]   
    for line in nodes:
        if line.find('vuln:reference',0,30)>0:
            t=getbid4str(line)
            if t:rs[1]=t
            continue
        i=line.find('vuln:summary')
        if i>0:
            j=line.find('vuln:summary',i+10)
            rs[2]=line[i+13:j-2]
    print rs
    return rs

def parsexml(path,node):
    f=open(path)
    nodes=[]
    rs=[]
    for line in f:
        if line.find('<'+node,0,20)>=0:
            nodes.append(line)
        elif line.find('</'+node,0,20)>=0:
            rs.append(parsenode(nodes))
            nodes=[]
        else:
            if nodes:
                nodes.append(line)
    f.close()
    return rs

def getallcve():
    print "Get all cve from data file......"
    for i in range(2002,2016):
        print "Parsing F:\\CVEVD\\cvedata\\nvdcve-2.0-%d.xml" %i
        rs=parsexml("F:\\CVEVD\\cvedata\\nvdcve-2.0-%d.xml" %i,'entry')
        cvelist.extend(rs)
    lib_pickle.dump2file('F:/CVEVD/cvelist.pkl',cvelist)

def getcvelist():
    print "get clear cvelist from pkl"
    cvelist=lib_pickle.get4file('F:/CVEVD/cvelist.pkl')
    for i in cvelist:
        i=isexist(cnvdlist,i[0],0)
        if i>=0:
            cvelist.remove(i)
    return cvelist
#=================================      

vcve=re.compile(r'cve *, *([\d-]+)')
vbid=re.compile(r'(bugtraq|bid) *, *(\d+)')
vcnvd=re.compile(r'cnvd *, *([\d-]+)')
vidpcre=(vcve,vbid,vcnvd)

def getvid4value(vs):
    for i in range(3):
        m=vidpcre[i].match(vs)
        if m:
            if i==1:
                return (i,m.group(2))
            else:
                return (i,m.group(1))
                        
def getvid4info(body):
    vid=[None,None,None]
    for info in body:
        if isinstance(info,tuple) and info[0]=='reference':
            rs=getvid4value(info[1])
            if rs:
                vid[rs[0]]=rs[1]
    return vid

def parserule(path):
    gvid=[]
    for line in open(path):
        line=line.strip()
        if line:
            rinfo=lib_rule.parserule(line)
            if rinfo:
                gvid.append(getvid4info(rinfo['body']))
    return gvid

#====================================
def isexist(lt,v,col=0):
    for i in range(len(lt)):
        if lt[i][col]==v:
            return i
    return -1


def removeexist(slist,value,col):
    i=isexist(slist,value,col)
    if i>=0:
        slist.pop(i)
        return 1
    return 0

def clearover(src,cnvdlist,cvelist):
    print "starting clear over......"
    for a in src:
        if a[0]:
            if removeexist(cnvdlist,a[0],0):continue
            if removeexist(cvelist,a[0],0):continue
        if a[1]:
            if removeexist(cnvdlist,a[1],1):continue
            if removeexist(cvelist,a[1],1):continue
        if a[2]:
            removeexist(cnvdlist,a[2],2)
            
    print "CVND",len(cnvdlist),"CVE",len(cvelist)
    lib_pickle.list2txt("F:/CVEVD/ccnvdlist.txt",cnvdlist,sep='\t')
    lib_pickle.list2txt("F:/CVEVD/ccvelist.txt",cvelist,sep='\t')
#======================================
              
try:  
    tmax=int(sys.argv[1])
    ivt=float(sys.argv[2])
    start=int(sys.argv[3])
    end=int(sys.argv[4])
except Exception:
    tmax=50
    ivt=1
    start=2002
    end=2016


getallcnvd()
if pos==1:
    print "craw ok"
    exit()
exit()
getallcve()

cnvdlist=getcnvdlist()
cvelist=getcvelist()
gvid=lib_pickle.get4file('F:/CVEVD/gvid.pkl')

print len(cnvdlist),len(cvelist),len(gvid)
clearover(gvid,cnvdlist,cvelist)
os.system('shutdown /s /t 3')


#cnvdlist=getcnvdlist()
#cvebid=[]
#getcnvdlist()
#mylock=threading.RLock()
#cvecnvd=getcvecnvd()
#print len(cvecnvd)
#lib_pickle.dict2txt('F:/CVEVD/cvecnvd.txt',cvecnvd)
#getcve()
#print len(cvebid)
#lib_pickle.dump2file('F:/CVEVD/cvebid.pkl',cvebid)
#lib_pickle.list2txt('F:/CVEVD/cvebid.txt',cvebid)
#gvid=parserule('F:/CVEVD/system.rules')
#print len(gvid)
#lib_pickle.dump2file('F:/CVEVD/gvid.pkl',gvid)