import lib_rule
import lib_TheardPool
import sys
import os
import threading

if len(sys.argv)<3:
    print "getinfo456.py inrule outinfo [errfile]"
    exit(1)

os.chdir(os.path.split(sys.argv[1])[0])
inrule=open(sys.argv[1])
outinfo=open(sys.argv[2],'w')
if len(sys.argv)>3:
    errfile=open(sys.argv[3],'w')
else:
    errfile=None


def printerror(err):
    if errfile:
        errfile.write(err+'\n')
    else:
        print err


def write2file(vinfo):
    print "task======",vinfo
    if vinfo[6]:
        desc=lib_rule.getdesc4cnvd(vinfo[6],'gbk')[1]
    elif vinfo[4]:
        desc=lib_rule.getdesc4cve(vinfo[4])[1]
        desc=lib_rule.transen2zh(desc,'gbk')
    elif vinfo[5]:
        desc=lib_rule.getdesc4bid(vinfo[5])[1]
        desc=lib_rule.transen2zh(desc,'gbk')
    else:
        #printerror("Error in %s" %vinfo[1])
        #exit(0)
        desc=""
    mylock.acquire()
    outinfo.write('@=========================\n')
    outinfo.write('msg:%s\n' %vinfo[0])
    outinfo.write('sid:%s\n' %vinfo[1])
    outinfo.write('gid:%s\n' %vinfo[2])
    outinfo.write('rev:%s\n' %vinfo[3])
    outinfo.write('cve:%s\n' %vinfo[4])
    outinfo.write('bid:%s\n' %vinfo[5])
    outinfo.write('cnvd:%s\n' %vinfo[6])
    outinfo.write('desc:%s\n' %desc)
    mylock.release()

i=1
pool=lib_TheardPool.threadpool()
mylock=threading.RLock()

dinfo=['msg','sid','gid','rev','reference']

for line in inrule:
    line=line.strip()
    if line:
        if line.find('noalert')>0:
            printerror("noalert: %s" %line)
            continue
        prule=lib_rule.parserule(line,i)
        vinfo=['msg','sid','gid','rev','','','']
        for info in prule['body']:
            try:
                index=dinfo.index(info[0].strip())
                if index<4:
                    vinfo[index]=lib_rule.mystrip(info[1])
                else:
                    key,value=info[1].split(',')
                    try:
                        index=['cve','bugtraq','cnvd'].index(key)
                        vinfo[index+4]=value
                    except ValueError:
                        pass
            except ValueError:
                pass
        #print "=============%s %d" %(vinfo[1],i)
        pool.addtask(write2file,(vinfo,))
        i+=1
pool.waitPoolComplete()
outinfo.write('@==============================')
