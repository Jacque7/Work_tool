#coding=gbk
import os
import sys
import re

reid=re.compile(r'\d+-?\d*')
idnames=('cve','cnnvd','bid','cnvd')
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
            #print "Error in eq!"
            return False
        if len(self.body)!=len(obj.body):
            return False
        '''
        for k,v in self.body.items():
            try:
                if obj.body[k]!=v:
                    return False
            except Exception:
                return False
        return True
        '''
        return self.body==obj.body
    
    def getbody(self):
        body=''
        for v in self.body:
            if isinstance(v,tuple):
                body+=(v[0]+':'+v[1]+'; ')
            else:
                body+=(v+'; ')
        return body
    
    
    def getinfo(self,key):
        if key:
            if self.meta[1][key] and self.meta[1][key]!='""':
                return self.meta[1][key]
            else:
                rs=self.meta[0][key]
                if rs=='""':
                    return None
                else:
                    return rs
                
        return ''
    
    def getrule(self,flag=0):
        if flag==1 and self.flag==0:
            return ''
        head=self.getinfo('head')
        msg=self.getinfo('msg')
        classtype=self.getinfo('classtype-danger')
        rev=self.getinfo('rev')
        body=self.getbody()
        return "%s(msg:%s; %sclasstype-danger:%s; tid:%s; rev:%s;)" %(head,msg,body,classtype,self.tid,rev)
    
    def writeinfo(self,outfile,flag=0):
        if flag==1 and self.flag==0:
            return ''
        outfile.write('@==========================\n')
        precise=self.getinfo('precise')
        atype=self.getinfo('atype')
        vos=self.getinfo('os')
        block=self.getinfo('block')
        pop=self.getinfo('pop')
        risk=self.getinfo('risk')
        ttype=self.getinfo('ttype')
        s='tid:%s\nprecise:%s\nos:%s\nblock:%s\npop:%s\nrisk:%s\nttype:%s\n' %(self.tid,precise,vos,block,pop,risk,ttype)
        outfile.write(s)
        p=('msg','cve','bid','cnvd','cnnvd','desc','version','solve','see','ename','atype')
        for k in p:
            v=self.getinfo(k)
            if v:
                if v[0]=='"' and v[-1]=='"':
                    v=v[1:-1]
                if k in idnames:
                    m=reid.search(v)
                    if m:
                        v=m.group()
                    else:
                        v=''
                outfile.write('%s:%s\n' %(k,v))
            
def regule(infile,outfile=None,head=False):
    if not os.path.isfile(infile):
        print "it is invaild file"
        exit(1)
    if not outfile:
        d,n=os.path.split(infile)
        outfile=d+'/re_'+n
    ifile=open(infile)
    ofile=open(outfile,'w')
    if head:ifile.readline()
    ree=re.compile(r'^\d{5,8}\$')
    for line in ifile:
        if ree.match(line):
            ofile.write('\n')
            ofile.write(line.replace('\n','').replace('\r','').strip())
        else:
            ofile.write(line.replace('\n','').replace('\r','').strip())
    ofile.close()
    ifile.close()

lre=re.compile(r'^(\d{5,8})\$(\d)\$(\d)\$(\d)\$(\d{1,2})\$(\d)\$(\d)\$\"(.*)\"\$(.*)\$(.*)\$(\".*\"|)\$(\".*\"|)\$(\".*\"|)\$(\".*\"|)\$(\".*\"|)\$(\".*\"|)\$(.*)\$(.*)')

def mysplit(line):
    rs=[]
    i=0
    l=len(line)
    f=0
    while True:
        if f:
            e=line.find('",',i)
            f=0
            if e==-1:
                f=2
                e=line.find('"',i)  
        else:
            e=line.find(',',i)
        
        if e==i:
            rs.append('')
            i=e+1
        else:
            if line[e]=='"':
                rs.append(line[i:e+1])
                i=e+2
            else:   
                rs.append(line[i:e])
                i=e+1
        if i==l:
            rs.append('')
            break
        if f==2:
            break
        if line[i]=='"':
            f=1
    if len(rs)!=18:
        print line
    return rs

def getvalues(line):
    line=line.strip()
    if not line:
        return 
    lt=line.split('$')
    if len(lt)!=18:
        #return mysplit(line)
        
        m=lre.match(line)
        if not m:
            print line
            return None
        else:
            return m.groups()
        
    else:
        return lt
def getinfo4table(ifile):
    if not os.path.isfile(ifile):
        print "it is a invaild file"
        exit(1)
    infodict={}
    for line in open(ifile):
        line=line.strip()
        if line:
            lt=getvalues(line)
            infodict[lt[0]]=lt[1:]
    return infodict

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
    dr.meta[flag]['head']=lrule[:index_h]
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
    

                
        