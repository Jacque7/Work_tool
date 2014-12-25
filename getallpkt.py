import os
import sys
import shutil

def ispcap(name):
    i=name.rfind('.')
    if i>0 and (name[i+1:]=='pcap' or name[i+1:]=='cap'):
        if name[:i].isdigit():
            if i>=4:
                return name[:i]
            else:
                return "DIR"
        else:
            return name[:i]
    return None

for line in open('F:\\Work\\trule_modify_project\\leave.txt'):
    line=line.strip()
    tid=line[:5]
    p=line.find('F:\\')
    if p>=0:
        p=line[p:]
        if os.path.isdir(p):
            fs=os.listdir(p)
            p=p+'/'+[i for i in fs if i[-5:]=='.pcap'][0]
        shutil.copy(p,'F:\\Work\\trule_modify_project\\pkt\\%s.pcap' %tid)
    else:
        print line
exit(1)
    
for p,d,f in os.walk(sys.argv[1]):
    for i in f:
        tid=ispcap(i)
        if tid:
            if tid=='DIR':
                print "%s\t%s" %(os.path.split(p)[1],p+'/'+i)
                continue
            print "%s\t%s" %(tid,p+'/'+i)