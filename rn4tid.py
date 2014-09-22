import lib_rule
import sys
import os
import shutil

def wincorrect(name):
    name=name.strip()
    winerror=":\/*?\"<>|"
    for i in range(len(winerror)):
        name=name.replace(winerror[i],'-')
    return name

def gettid(msg1):
    for tid,msg2 in ipsrules.items():
        if msg1==msg2[0]:
            return tid
    return None

if len(sys.argv)<3:
    print "rn4tid.py grule ips"
    print "grule,path of grule file"
    print "ips,path of ips rule file"
    exit(1)
p1=sys.argv[1] #grule
p2=sys.argv[2] #ips rule
path,f=os.path.split(p1)
os.chdir(path)
try:
    os.mkdir('tid')
    os.mkdir('msg')
except Exception:
    pass

grules=lib_rule.getinfo4grule(p1)
ipsrules=lib_rule.getinfo4rule(p2)

for grule in grules:
    msg=grule['msg']
    #if msg[-1].isdigit():
    #    msg=msg+"\xe6\x94\xbb\xe5\x87\xbb"
    ename=wincorrect(grule['ename'])
    tid=gettid(msg)
    if not tid:
        print ename
        continue
    msg=msg.decode('utf8')
    shutil.copy(ename+"/5.pcap","tid/"+tid+".pcap")
    shutil.copy(ename+"/5.pcap","msg/"+msg+".pcap")
    