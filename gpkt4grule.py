import os
import sys

src='F:/Work/IDP/Allowed_1_5/Allowed'
#src='F:\\Work\\IDP\\CVE-2012\\CVE'
#gpkt4grule grule
if len(sys.argv)<2:
    print "gpkt4rule path,parameter path is grule"
    exit(1)
path=sys.argv[1]
d,name=os.path.split(path)
os.chdir(d)

f=open(name)
fw=open('name.txt','w')

def wincorrect(name):
    name=name.strip()
    winerror=":\/*?\"<>|"
    for i in range(len(winerror)):
        name=name.replace(winerror[i],'-')
    return name

def cpdir(src,dst):
    try:
        os.mkdir(dst)
    except Exception:
        pass
    cmd="xcopy \""+src+"/"+dst+"\" \""+dst+"\""
    os.system(cmd)
    
for line in f:
    subs=line.split(':',1)
    if subs[0]=='ename':
        dst=wincorrect(subs[1])
        print subs[1][:-1]
        fw.write(dst+"\n")
        cpdir(src,dst)
