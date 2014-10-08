#!/usr/bin/python

import subprocess
import os
import sys
import lib_pickle
import lib_rule
import time
import walk


cwdpcap=""
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

def getinfo4stdout(subp):
    global grs
    global cwdpcap
    rs=subp.stdout.read().split("\r\n")
    for line in rs:
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
        
        
def startsnort(pcap):
    global grs
    #cmd="snort -r "+pcap+" -A console -c "+etc+" -l "+log
    cmd="snort.bat "+pcap
    subp=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE)#,shell=True)
    subp.wait()
    getinfo4stdout(subp)
    

def getpcap(dir):
    flist=os.listdir(dir)
    rpf=[]
    for i in flist:
        ext=os.path.splitext(i)[1]
        try:
            extlt.index(ext)
            rpf.append(i)
        except Exception:
            pass
    return rpf

def snortdir(path):
    flist=os.listdir(path)
    for i in flist:
        p1=path+"/"+i
        if os.path.isfile(p1):
            if ispcap(p1):
                startsnort(p1)
                
        elif os.path.isdir(p1):
            plist=getpcap(p1)
            for j in plist:
                p2=p1+"/"+j
                startsnort(p2)
                
def findlist(path):
    flist=os.listdir(path)
    for i in flist:
        if i=="pcap.list":
            return 1
    return 0

def snortlist(path):
    if not findlist(path):
        pcaplist,bpcaplist=walk.getpcaplist_2(path)
        f=open("pcap.list",'w')
        for i in pcaplist:
            f.write(i+"\n")
        f.close()
        f=open('bpcap.list','w')
        for i in bpcaplist:
            f.write(i+'\n')
        f.close()
    plist=args['-p']+"\\pcap.list"
    print "detection file from "+plist
    print "detection starting...."
    subp=subprocess.Popen("D:/Snort/ssnort.bat -flist \""+plist+"\"",stdin=subprocess.PIPE,stdout=subprocess.PIPE)#,shell=True)
    #stdout, stderr = subp.communicate()
    #subp.wait()
    if not subp.returncode:
        getinfo4stdout(subp)
        

def analysis(grs,grule):
    for i in grule:
        if grs.get(i[0]):
            #print "alert:",i[0],"msg:",i[1],"numbers:",grs[i[0]][1]
            #f.write("alert:"+id[0]+"\t"+i[i]+"\n")
            pass
        else:
            print "sid:",i[0],"msg:",i[1]
            
  
            
args={'-p':"",'-r':'','-rpk':'','-o':''}

if len(sys.argv)<2:
    print "para error,again"
    print "-p dir of you test pcap file"
    print "-r rule file for you want to check"
    print "-rpk data file of rule file,increase efficiency"
    print "-o file path of print alert info "
    exit(1)


i=1
while i<len(sys.argv):
    key=sys.argv[i]
    if args.get(key)!=None:
        if key=='-rpk':
            args[key]='1'
            i+=1
        else:
            args[key]=sys.argv[i+1]
            i+=2
    else:
        print "error parameter...again"
        exit()      
if args['-p']=='':
    args['-p']=os.getcwd()
if not os.path.exists(args['-p']):
    print "the path is not exists"
    exit(1)
if not os.path.isdir(args['-p']):
    print "the path must be a dir"
    exit(1)

os.chdir(args['-p'])
if args['-r']!='':
    if not os.path.isfile(args['-r']):
        print "%s is not exist,please input real path for rule file" %args['-r']
        exit(1)
    grs=lib_rule.getinfo4rule(args['-r'])
    print "load numbers of rule:",len(grs)
    if len(grs):
        lib_pickle.dump2file(args['-p']+"/rule.pkl",grs)
if args['-rpk']!='':
    if os.path.isfile("rule.pkl"):
        grs=lib_pickle.get4file("rule.pkl")
        print "load numbers of rule:",len(grs)
    else:
        print "rule.pkl is not exist,please input real path for rule file"
        exit(1)

if not len(grs):
    print "load rules error,again"
    exit(1)

snortlist(args['-p'])
print "snort exit..."
rsf=open('rs.txt','w')
rsf.write(str(grs))
rsf.close()

if args['-o']!='':
    print "msg:the jobs is over,out the result"
    try:
        outf=open(args['-o'],'w')
        for sid,info in grs.items():
            if len(info)<2:
                print sid+'\t'+info[0]
                continue
            outf.write(sid+'\t'+info[0]+'\t')
            for pcap in list(info[1]):
                outf.write(pcap+'\t')
            outf.write('\n')
        outf.close()
    except Exception:
        print "alert infomation dump to file fail..."
        exit(0)

    


            
    
            

