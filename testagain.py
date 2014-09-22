import os
import sys
import lib_rule


def getresult(path):
    rs=[]
    f=lib_rule.searchtidrules(path)
    if not f:
        return None
    print f
    grs=lib_rule.getinfo4rule(f,1)
    for tid,value in grs.items():
        try:
            tids.index(tid)
            if os.path.isfile(path+'/tid/'+tid+'.pcap'):
                rs.append(tid+'\t'+'\t'.join(value)+'\t'+path+'/tid/'+tid+'.pcap')
            else:
                print tid,value[0]
                rs.append(tid+'\t'+'\t'.join(value))
            tids.remove(tid)
        except Exception:
            pass
    return rs
    #for tid in tids:
    #    try:
    #        tmp=grs[tid] #tid msg rule
    #        if os.path.isfile(path+'/tid/'+tid+'.pcap'):
    #            rs.append(tid+'\t'+'\t'.join(tmp)+'\t'+path+'/tid/'+tid+'.pcap')
    #        else:
    #            rs.append(tid+'\t'+'\t'.join(tmp))
    #    except Exception:
    #        pass
if len(sys.argv)<3:
    print "testagain dir file"
    print "dir: directory for packet"
    print "file: file for tid"
    
if not os.path.isdir(sys.argv[1]):
    print "Please input vaild dir"
    exit(1)
if not os.path.isfile(sys.argv[2]):
    print "Please input vaild file"
    exit(1)
currentd=sys.argv[1]
try:
    os.chdir(currentd)
    fw_table=open('testagain.csv','w')
except Exception:
    print "Have Unknow Error"
    exit(1)
    
tids=lib_rule.gettid4file(sys.argv[2])
lts=os.listdir(currentd)
for lt in lts:
    if os.path.isdir(currentd+'/'+lt+'/tid'):
        rs=getresult(currentd+'/'+lt)
        if rs:
            for line in rs:
                fw_table.write(line+'\n')
for tid in tids:
    print tid
fw_table.close()
