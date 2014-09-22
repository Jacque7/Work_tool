import os
import sys
import lib_pickle
# testanalysis.py logname rulename outname
cwdpcap=""
def getinfo(line):
    global cwdpcap
    if line[:7]=="Reading":
        cwdpcap=getcwdpcap(line)
        return
    s=line.find("[**]")
    if s<0:
        return None
    f=line.find(":",s+8)
    #end=line.find("[**]",f+4)
    return line[s+8:f]#,line[f+4:end-1]

def getcwdpcap(line):
    s=line.find('"')
    e=line.find('"',s+1)
    return line[s+1:e]

if len(sys.argv)<4:
    print "parameter is lack,again"
    exit(0)

logname=sys.argv[1]
rulename=sys.argv[2]
outfname=sys.argv[3]
grs=lib_pickle.get4file(rulename)
"""
f=open(logname)
for line in f:
    sid=getinfo(line)
    if not sid:
        continue
    if len(grs[sid])<2:
        grs[sid].append(set([cwdpcap]))
    else:
        grs[sid][1].add(cwdpcap)


outf=open(outfname,'w')
"""
for sid,info in grs.items():
    if len(info)<2:
        print sid,'\t',info[0]
        continue
    outf.write(sid+'\t'+info[0]+'\t')
    for pcap in list(info[1]):
        outf.write(pcap+'\t')
    outf.write('\n')
outf.close()
lib_pickle.dump2file("F:/packet/frs.pkl",grs)



    