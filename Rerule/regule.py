
import os
import sys
import re
import lib_pickle

class drule:
    def __init__(self):
        self.flag=0
        self.body=[]
        self.tid=0
        self.meta=[{'head':None,'msg':None,'classtype-danger':None,'tid':None,'eventype':None,\
                    'precise':None,'pop':None,'risk':None,'ttype':None,'os':None,\
                    'block':None,'bid':None,'cve':None,'atype':None,'desc':None,\
                    'version':None,'see':None,'cnvd':None,'cnnvd':None,'ename':None,\
                    'solve':None,'rev':None},\
                   {'head':None,'msg':None,'classtype-danger':None,'tid':None,'eventype':None,\
                    'precise':None,'pop':None,'risk':None,'ttype':None,'os':None,\
                    'block':None,'bid':None,'cve':None,'atype':None,'desc':None,\
                    'version':None,'see':None,'cnvd':None,'cnnvd':None,'ename':None,\
                    'solve':None,'rev':None}]
        
    def __eq__(self,obj):
        if not isinstance(obj,drule):
            print "Error in eq!"
            return False
        if len(self.body)!=len(obj.body):
            return False
        for k,v in self.body.items():
            try:
                if obj.body[k]!=v:
                    return False
            except Exception:
                return False
        return True
    
    def getbody(self):
        body=''
        for k,v in self.body:
            if v:
                body+=(k+':'+v+'; ')
            else:
                body+=(k+'; ')
        return body
    
    def getinfo(self,s):
        if s:
            if self.rmeta[s]:
                return self.rmeta[s]
            else:
                return self.dmeta[s]
        return ''
    
    def getrule(self,flag=0):
        if flag!=self.flag and self.flag!=2:
            return ''
        head=self.getinfo('head')
        msg=self.getinfo('msg')
        classtype=self.getinfo('classtype')
        rev=self.getinfo('rev')
        body=self.getbody()
        return "%s (msg:\"%s\"; %sclasstype:%s; tid:%s; rev:%s;)" %(head,msg,body,classtype,tid,rev)
            
def regule(infile,outfile=None,head=False,split=',',sep='"',cols=18):
    if not os.path.isfile(infile):
        print "it is invaild file"
        exit(1)
    if not outfile:
        d,n=os.path.split(infile)
        outfile=d+'/re_'+n
    ifile=open(infile)
    ofile=open(outfile,'w')
    if head:ifile.readline()
    ree=re.compile(r'^\d{5,8},')
    for line in ifile:
        if ree.match(line):
            ofile.write('\n')
            ofile.write(line.replace('\n','').replace('\r','').strip())
        else:
            ofile.write(line.replace('\n','').replace('\r','').strip())
    ofile.close()
    ifile.close()



lre=re.compile(r'(\d{5,8}),(\d),(\d),(\d),(\d{1,2}),(\d),(\d),\"(.*)\",(.*),(.*),(\".*\"|),(\".*\"|),(\".*\"|),(\".*\"|),(\".*\"|),(\".*\"|),(.*),(.*)')

def getvalues(line):
    line=line.strip()
    if not line:
        return 
    lt=line.split(',')    
    if len(lt)!=18:
        m=lre.match(line)
        if not m:
            print line
            return None
        else:
            return m.groups()
    else:
        return lt
    
def anaysisrule(lrule,flag=0):
    dr=drule()
    i=1
    cur=1
    classfy=['msg','classtype-danger','tid','rev']
    if lrule[-2:]!=';)':
        print("loss ;)")
        return 
    index_h=lrule.find('(msg:')
    if index_h<=0:
        print("'(msg' is must,this is a invaild rule")
        return 
    body=lrule[index_h:]
    while i<len(body):
        if body[i]==';':
            key=body[cur:i].strip()
            #print key
            i=i+1
            cur=i
            dr.body.append(key)
            continue
        
        if body[i]==':':
            key=body[cur:i].strip()
            j=i+1
            while 1:
                j=body.find(';',j)
                if j>0 and body[j-1]=='\\':
                    j+=1
                    continue
                break         
            value=body[i+1:j].strip()
            #print key,value
            try:
                index=classfy.index(key)
                dr.meta[flag][classfy[index]]=value
            except ValueError:
                dr.body.append((key,value))
            i=j+1
            cur=i
            continue
        i+=1
    return dr

eventype=["低风险事件--网络访问类","低风险事件--扫描类","低风险事件--木马类","低风险事件--拒绝服务类",\
          "低风险事件--系统漏洞类","低风险事件--WEBCGI攻击类","低风险事件--RPC攻击类","低风险事件--HTTP攻击类",\
          "低风险事件--溢出攻击类","中风险事件--扫描类","中风险事件--木马类","中风险事件--拒绝服务类",\
          "中风险事件--系统漏洞类","中风险事件--WEBCGI攻击类","中风险事件--RPC攻击类","中风险事件--HTTP攻击类",\
          "中风险事件--溢出攻击类","中风险事件--网络访问类","高风险事件--溢出攻击类","高风险事件--蠕虫类",\
          "高风险事件--HTTP攻击类","高风险事件--木马类","高风险事件--拒绝服务类","高风险事件--系统漏洞类",\
          "高风险事件--WEBCGI攻击类","高风险事件--RPC攻击类","所有事件"]


def getevetype(line):
    a=line.find('name')
    b=line.find('rules',a)
    name=line[a+5:b].strip()
    evetype=eventype.index(name)+1
    a=line.find('"',b)
    b=line.find('"',a+1)
    ids=line[a+1:b].split(',')
    return evetype,ids

def anasis(frule,flag=0):
    eventdict={}
    rulelist=[]
    for line in open(frule):
        line=line.strip()
        if line:
            if line[:8]=='eventset':
                evety,ids=getevetype(line)
                for tid in ids:
                    tid=tid[:-2]
                    if eventdict.has_key(tid):
                        eventdict[tid].append(evety)
                    else:
                        eventdict[tid]=[evety]
                continue
            rs=anaysisrule(line,flag)
            if not rs:
                print line
            else:
                rs.flag=flag
                rulelist.append(rs)
    for i in range(len(rulelist)):
        try:
            rulelist[i].meta[flag]['eventype']=eventdict[rulelist[i].meta[flag]['tid']]
        except KeyError:
            pass
    return rulelist
    #lib_pickle.dump2file(out,rulelist)
    
anasis("F:\\Work\\rerule\\debug\\ips-v2014.10.09.rules")
                
        