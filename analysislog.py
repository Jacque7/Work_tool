import os
import sys
import lib_rule

def getcwdpcap(line):
    s=line.find('"')
    e=line.find('"',s+1)
    return line[s+1:e]

def getinfo(line):
    global cwdpcap
    if line[:7]=="Reading":
        cwdpcap=getcwdpcap(line)
        return "",""
    s=line.find("[**]")
    if s<0:
        return "",""
    f=line.find("]",s+8)
    end=line.find("[**]",f+4)
    return line[s+8:f-2],line[f+4:end-1]

def analysis(log):
    global grs
    global cwdpcap
    f=open(log)
    for line in f:
        if not line:
            continue
        sid,msg=getinfo(line)
        if not sid:
            continue
        try:
            if len(grs[sid])<2:
                grs[sid].append(set([cwdpcap]))
            else:
                grs[sid][1].add(cwdpcap)
        except Exception:
            grs[sid]=[msg,set([cwdpcap])]

if len(sys.argv)<4:
    print "use: logfile rulesfile outfile"
    exit(1)
log=sys.argv[1]
rule=sys.argv[2]
out=sys.argv[3]
grs=lib_rule.getinfo4rule(rule)
cwdpcap=None
print "load numbers of rule:",len(grs)
analysis(log)

outf=open(out,'w')
for sid,info in grs.items():
    if len(info)<2:
        print sid+'\t'+info[0]
        continue
    outf.write(sid+'\t'+info[0]+'\t')
    for pcap in list(info[1]):
        outf.write(pcap+'\t')
    outf.write('\n')
outf.close()



