#import shutil
import os
import sys

def getaskname(path):
    names=[]
    for line in open(path):
        name=line.strip()
        if name[0]!='#' and len(name)>5:
            names.append(name)
    return names
'''
def getvlist(path):
    vlist=[]
    for line in open(path):
        vinfo=line.strip()
        if vinfo[0]!='#' and len(vinfo)>10:
            vlist.append(getvinfo(vinfo))
    return vlist

def getvinfo(vinfo):
    vinfos=vinfo.split('\t')
    vid=getid(vinfos[3])
    ipt=getipt(vinfos[-1])
    return (vinfos[1],vid,ipt)
'''
def getvlist(path):
    vlist={}
    i=0
    for line in open(path):
        i+=1
        vinfo=line.strip()
        if vinfo[0]!='#' and len(vinfo)>10:
            vinfos=vinfo.split(',')
            key=vinfos[0][:vinfos[0].find('(http')].strip()
            if key[0]=='\'' or key[0]=='\"':
                key=key[1:]
            vid=getid(vinfos[2])
            ipt=getipt(vinfos[-1])
            if vlist.get(key):
                #print key,vlist[key]
                continue
            key=wincorrect(key)
            vlist[key]=(vid,ipt)
    print len(vlist),i
    return vlist


def getid(idtext):
    org=idtext.find('CVE')
    cve=None
    bid=None
    if org>=0:
        cve=idtext.find(' ',org+4)
        cve=idtext[org+4:cve]
    org=idtext.find('BID')
    if org>=0:
        bid=idtext.find(' ',org+4)
        bid=idtext[org+4:bid]
    return (cve,bid)

def getipt(iptext):
    ip=iptext.find(' ')
    port=iptext.find(':',ip+1)
    end=iptext.find('-',port+1)
    return (iptext[ip+1:port],iptext[port+1:end])

def wincorrect(name):
    winerror=":\/*?\"<>|"
    for i in range(len(winerror)):
        name=name.replace(winerror[i],'-')
    return name

def myfilter(vname,pname,oname,ip,port):
    vname=wincorrect(vname)
    oname='packet/pp/'+vname+'.pcap'
    if not os.path.isdir('packet/'+vname):
        os.mkdir('packet/'+vname)
    cmd='windump -s 0 -w \"%s\" -r %s host %s' %(oname,pname,ip)
    if port:
        cmd+=' and port '+port
    print cmd
    os.system(cmd)

def getvfile(dd):
    lt=os.listdir(dd)
    for l in lt:
        if os.path.isdir(dd+'/'+l):
            continue
        name,ext=os.path.splitext(l)
        if ext=='.vlist':
            if os.path.isfile(dd+'/'+name+'.pcap'):
                return name
            print "Have not exist pcap in %s" %dd
            
def print2grule(ename,cve,bid):
    grule.write('ename:%s\n' %ename)
    if cve:
        grule.write('cve:%s\n' %cve)
    if bid:
        grule.write('bid:%s\n' %bid)
    grule.write('@====================================================\n')
    
if len(sys.argv)<3:
    print "USE: filterpcap dir task"
    print "dir: work directory"
    print "tesk: task file"
    exit(1)
if not (os.path.isdir(sys.argv[1]) and os.path.isfile(sys.argv[2])):
        print "You have must input vaild dir and task file"
        exit(1)
sdir=sys.argv[1]
task=sys.argv[2]
try:
    os.chdir(sdir)
    os.mkdir('packet')
except Exception:
    pass
vnames=getaskname(task)

for d in os.listdir(os.getcwd()):
    if os.path.isfile(d):
        continue
    name=getvfile(d)
    if not name:
        continue
    vlist=getvlist(d+'/'+name+'.vlist')
    i=0
    for vname in vnames:
        if vlist.get(vname):
            vname=wincorrect(vname)
            myfilter(vname,d+'/'+name+'.pcap','packet/'+vname+'/'+name+'.pcap',vlist[vname][1][0],vlist[vname][1][1])
        else:
            print vname

#vlist=getvlist('F:/Work/BPS/2013_3/3.vlist')
if os.path.isfile('packet/vinfo.grule'):
    grule=open('packet/vinfo.grule','a+')
else:
    grule=open('packet/vinfo.grule','w')
    grule.write('@====================================================\n')
for vname in vnames:
    if vlist.get(vname):
        print2grule(vname,vlist[vname][0][0],vlist[vname][0][1])
        

