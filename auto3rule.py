# -*- coding: utf-8 -*-
import lib_rule
import lib_pickle
import lib_threadpool
import os
import sys
import shutil
import re

#work model:
#1 create general rule from rule data file
#2 get information from internet or packet file
argvs={"-f":"","-cid":666666,"-work":"1","-gcnvd":0,"-gversion":0,"-gdesc":0,\
       "-tran":0,"-debug":0,'-gmsg':0,'-gbid':0,'-gauto':0,"-admin":0,"-multi":0,\
       "-desc":"desc","-msg":"msg","-see":"see","-version":"version","-cve":"cve","-cnnvd":"cnnvd",\
      "-bid":"bid","-cnvd":"cnvd","-sip":"sip","-sport":"sport","-dip":"dip","-type":"type","-flow":"flow","-protocol":"protocol",\
      "-dport":"dport","-solve":"solve","-sid":"sid","-ename":"ename","-body":"body","-tid":"tid","-cname":"cname"}
########################################################################
class rule:
    #----------------------------------------------------------------------
    def __init__(self):
        self.protocol="tcp"
        self.sip="any"
        self.sport="any"
        self.dip="any"
        self.dport="any"
        self.flow="default"
        self.body=""
        self.msg=""
        self.sid=""
        self.rev='1'
        self.desc=""
        self.see=""
        self.cve=""
        self.bid=""
        self.cnvd=""
        self.cnnvd=""
        self.version=""
        self.solve="升级系统版本到最新"
        self.start=0
        self.ref=""
        self.cname=""
        self.ename=""
        self.tid=""
        self.type=""
        self.edesc=""
        self.redundancy=""
        self.report=re.compile(r"\d+")
        self.repro=re.compile(r'(tcp|udp)',re.I)
    def combin(self):
        if self.bid!='' or self.cve!='' or self.cnvd!='':
            ref=""
            if self.cve!="":
                ref=ref+"reference:cve,"+self.cve+"; "
            if self.bid!="":
                ref=ref+"reference:bugtraq,"+self.bid+"; "                
            if self.cnvd!="":
                ref=ref+"reference:cnvd,"+self.cnvd+"; "
            self.ref=ref
            
        return None
    
    def getport(self,ports):
        lt=ports.split(',')
        if len(lt)==1:
            return lt[0].strip()
        else:
            s='['
            for i in lt:
                s+=i.strip()+' '
            return s.strip()+']'
        
    def getinfo(self,s):
        if s=='ename':
            return self.ename
        
    def getbody(self):
        global argvs
        if argvs['-debug']:
            self.dport="any"
            self.sport="any"
        if self.repro.match(self.protocol):
            if (self.sport=='any' and self.dport=='any') and (not argvs['-debug']):
                self.puterror("tcp and udp port should use explicit port")
    
        body="alert "+self.protocol+" "+self.sip+" "+self.sport+" -> "+\
            self.dip+" "+self.dport+" (msg:\""+self.msg.decode('utf8').encode('gbk')+"\"; "
        if self.flow=="default" and self.protocol=='tcp':
            if self.sport==self.dport=='any':
                pass
            elif self.sport.isdigit():
                body+="flow:to_client,established; "
            elif self.dport.isdigit():
                body+="flow:to_server,established; "
        elif self.flow=="server":
            body+="flow:to_server,established; "
        elif self.flow=="client":
            body+="flow:to_client,established; "
        body+=self.body
        body+=" "
        self.combin()
        if self.ref!="":
            body+=self.ref
        if self.sid=="":
            #body+="sid:"+self.tid+"; "
            body+="sid:"+str(argvs['-cid'])+"; "
            argvs['-cid']=argvs['-cid']+1
        body+="rev:"+self.rev+";)\n"
        return body
    
    def puterror(self,msg):
        print "Error rule in line:",self.start,'\tmsg:',msg
        #print "tid:",self.tid,msg
        #exit(1)
        
    def authdata(self,type=0):
        if self.msg=="":
            if self.cname:
                self.msg=self.cname
            else:
                self.puterror("miss msg")
        if type:
            return
        if self.body=="":
            self.puterror("miss body")
        if self.version=="":
            self.puterror("miss version")
        if self.desc=="":
            self.puterror("miss desc")
        if self.see=="":
            if self.bid:
                self.see="http://www.securityfocus.com/bid/"+self.bid
            elif self.cve:
                self.see="http://www.cve.mitre.org/cgi-bin/cvename.cgi?name="+self.cve
            else:
                self.puterror("miss see")
        if self.ename=="":
            self.puterror("miss ename")
        return True
    
    def checkcontent(self,body,offset):
        if self.body.find(" nocase;",offset)<0:
            self.puterror("lack nocase for uricontent/content")
        if self.body.find(" offset:",offset)<0:
            self.puterror("lack offset for uricontent/content")
        if self.body.find(" depth:",offset)<0:
            self.puterror("lack depth for uricontent/content")
    def checkpcre(self,body,offset):
        s=body.find('/',offset)
        e=body.find("\";",s+1)
        f=e-5;
        
        if s<0 or f<0 or e<0:
            self.puterror("pcre sytanx error,lack /,\",; ,pcre format: \"/xxxx/\"; ")
            #print body,body+";"
            return
        i=s+1
        while i<f:
            if body[i]=='.':
                c=body[i+1]
                if (c!='+' or c!='*' or c!='{') and ('\\'!=body[i-1]):
                    self.puterror("pcre syntax is error for . in %d" %i)
                    return
            if body[i]=="/":
                c=body[i-1]
                if c!='\\':
                    self.puterror("pcre syntax is error for / in %d" %i)
                    return
            i+=1
                
    def checkbody(self):
        if self.body.find("uricontent:\"")==0 or self.body.find("content:\"")==0:
            a=self.body.find("\";")
            if a>0:
                self.checkcontent(self.body,a+2)
            else:
                self.puterror("lack quota or semicolon for uricontent/content")
            """
            if self.body.find(" uricontent:\"",a+2)>0 or self.body.find(" content:\"",a+2)>0:
                a=self.body.find("\";",a+5)
                if a>0:
                    self.checkcontent(self.body,a+2)
                else:
                    self.puterror("lack quota or semicolon for uricontent/content
            """
        p=self.body.find("pcre:")
        if p>=0:
            self.checkpcre(self.body,p+5)
            
    def clearmsg(self):
        s="\'\"!@#$%^&+\\/?;.！”“（），。？；"
        remsg=re.compile(r"(\’|\'|\"|\!|@|#|$|\%|\^|\&|\+|\\|\/|\?|\;|\.|！|”|“|（|）|，|。|？|；)")
        #try:
        #    self.msg=self.msg.decode('gbk').encode('utf8')
        #except Exception:
        #    pass
        if not self.msg:
            return
        self.msg=remsg.sub('',self.msg)
        if self.msg[-1]==')':
            return
        if self.msg[-6:]!="攻击" and (not self.msg[-1].isdigit()):
            self.msg=self.msg+"攻击"
        """
        msg=self.msg
        for i in range(len(self.msg)):
            msg=msg.replace(self.msg[i],'')
        self.msg=msg
        """
    def output(self,f):
        self.authdata()
        self.checkbody()
        self.clearmsg()
        body=self.getbody()
        global gobject
        gobject.append(self)
        #f.write("#=========================================\n")
        f.write(body)
        """
        f.write("#漏洞描述:"+self.desc+"\n")
        f.write("#英文名称:"+self.ename+"\n")
        f.write("#其他资料:"+self.see+"\n")
        f.write("#解决方法:"+self.solve+"\n")
        f.write("#影响系统:"+self.version+"\n")
        if self.ref!="":
            f.write("#"+self.ref+"\n")
        f.flush()
        """
    
    def setcve(self,data):
        if data.find("CVE")>=0 or data.find("cve")>=0:
            cveid=data[4:]
        else:
            cveid=data
        self.cve=cveid
    
    def setbid(self,data):
        self.bid=data.split(',')[0]
    
    def setdata(self,type,data):
        if type=="cve":
            self.setcve(data)
        elif type=="bid":
            self.setbid(data)
        elif type=="cnvd":
            self.cnvd=data
        elif type=="body":
            self.body=data
        elif type=="sport":
            self.sport=self.getport(data)
        elif type=="dport":
            self.dport=self.getport(data)
        elif type=="body":
            self.body=data
        elif type=="desc":
            self.desc=data
        elif type=="solve":
            self.solve=data
        elif type=="version":
            self.version=data
        elif type=="cname":
            self.cname=data
        elif type=="ename":
            self.ename=data
        elif type=="msg":
            self.msg=data
        elif type=="cnnvd":
            self.cnnvd=data
        elif type=="protocol":
            self.protocol=data
            if self.protocol=='ip' or self.protocol=="IP":
                self.sport='any'
                self.dport='any'
        elif type=="rev":
            self.rev=data
        elif type=="tid":
            self.tid=data
        elif type=="type":
            self.type=data
        elif type=="cname":
            self.cname=data
        elif type=="flow":
            self.flow=data
        return
    
def setparameter(para,i):
    pname=["-gcnvd","-gdesc","-gversion","-tran","-debug","-gmsg","-gbid","-gauto","-admin"]
    if para in pname:
        argvs[para]=1
        return 1
    
    value=sys.argv[i+1]
    pname=['-cid','-multi']
    if para in pname:
        argvs[para]=int(value)
    else:
        argvs[para]=value
    return 2

#set attributle value for struct of rule
def opera_data(lnum,line,srule):
    values=argvs.values()
    line=line.strip()
    ls=line.split(":",1)
    if len(ls)!=2:
        print "Error msg in lines:",lnum
        return
    tmp=("uricontent","content","pcre")
    
    try:
        tmp.index(ls[0])
        srule.setdata("body",line)
        return
    except Exception:
        pass
    
    for i in argvs:
        value=argvs[i]
        if value==ls[0]:
            srule.setdata(i[1:],ls[1])
            return
    #print "have error in lines:",lnum
    #exit(1)
    srule.redundancy+=line+"\n"
    
#read file and structure rule object and output
def opera(func):
    f=argvs['-f']
    f=open(f,'r')
    srule=None
    threadpool=None
    if argvs['-multi']>1:
        threadpool=lib_threadpool.threadpool(func)
    lnum=0
    for line in f:
        lnum+=1
        if line[0]=="#":
            continue
        if line[0]=="@":
            if srule:
                if threadpool:
                    threadpool.addtask(srule)
                else:
                    func(srule)
                srule=rule()
                srule.start=lnum
                continue
            else:
                srule=rule()
                srule.start=lnum
                continue
        if srule:
            opera_data(lnum,line,srule)
        else:
            print "use '@' in begin of line for every struct grule"
            exit(1)
    if threadpool:
        threadpool.waitcomplete()
        
    if argvs['-work']=='1':
        ofile.write('@==============================')
  #  if srule:
  #      func(srule)
gobject=[]
def typeaction(rinstan):
    if not rinstan.type:
        return 0
    path="F:\\topsecwork\\"
    if rinstan.type=="check":
        try:
            shutil.move(path+"task\\guo\\"+rinstan.tid,path+"backup\\check")
            print "move:",rinstan.tid
        except Exception:
            if os.path.exists(path+"task\\guo\\"+rinstan.tid):
                print "Can't move:",rinstan.tid
            pass
        return 1
    elif rinstan.type=="sql inject":
        print "sql inject:",rinstan.tid
        return 1
    elif rinstan.type=="Directory Traversal":
        print "Directory Traversal:",rinstan.tid
        return 1
    elif rinstan.type=="same":
        print "same:",rinstan.tid
        return 1
    elif rinstan.type=="ignore":
        print "ignore:",rinstan.msg
        return 1
    return 0
        
import random
gmsg=[]

def outdata(rinstan):
    rinstan.authdata(1)
    rinstan.clearmsg()
    global gobject
    if typeaction(rinstan):
        return
    gobject.append(rinstan)
    while rinstan.msg in gmsg:
        rinstan.msg=rinstan.msg+str(random.randint(1,9))
    gmsg.append(rinstan.msg)
    print rinstan.msg.decode('utf8')
    ofile.write("@%d==========================================\n" %len(gmsg))
    if rinstan.body:
        line="body:"+rinstan.body+"\n"
        ofile.write(line)

    if rinstan.cve:
        line="cve:"+rinstan.cve+"\n"
        ofile.write(line)
 
    if rinstan.cnvd:
        line="cnvd:"+rinstan.cnvd+"\n"
        ofile.write(line)
        
    if rinstan.cnnvd:
        line="cnnvd:"+rinstan.cnnvd+'\n'
        ofile.write(line)

    if rinstan.bid:
        line="bid:"+rinstan.bid+"\n"
        ofile.write(line)

    if rinstan.tid:
        line="tid:"+rinstan.tid+"\n"
        ofile.write(line)
        
    if rinstan.sport and rinstan.sport!='any':
        line="sport:"+rinstan.sport+"\n"
        ofile.write(line)
        
    if rinstan.dport and rinstan.dport!='any':
        line="dport:"+rinstan.dport+"\n"
        ofile.write(line)

    if rinstan.msg:
        line="msg:"+rinstan.msg+"\n"
        ofile.write(line)
        #try:
        #    ofile.write(line)
        #except Exception:
        #    ofile.write(line.encode('utf-8'))

    if rinstan.protocol and rinstan.protocol!='tcp':
        line="protocol:"+rinstan.protocol+"\n"
        ofile.write(line)

    if rinstan.rev and rinstan.rev!='1':
        line="rev:"+str(rinstan.rev)+"\n"
        ofile.write(line)
  
    if rinstan.see:
        line="see:"+rinstan.see+"\n"
        ofile.write(line)

    if rinstan.solve:
        line="solve:"+rinstan.solve+"\n"
        ofile.write(line)

    if rinstan.cname:
        line="cname:"+rinstan.cname+"\n"
        ofile.write(line)
    
    if rinstan.ename:
        line="ename:"+rinstan.ename+"\n"
        ofile.write(line)
    if rinstan.version:
        line="version:"+rinstan.version+"\n"
        ofile.write(line)
        #try:
        #    ofile.write(line)
        #except Exception:
        #    ofile.write(line.encode('utf8'))
    if rinstan.redundancy:
        ofile.write(rinstan.redundancy)       
    if rinstan.desc:
        line="desc:"+rinstan.desc+"\n"
        ofile.write(line)
        #try:
        #    ofile.write(line)
        #except Exception:
        #    ofile.write(line.encode('utf-8'))
    #ofile.flush()

def opera_crule(rinstan):
    if rinstan.cve and (rinstan.bid=='' or rinstan.desc=='') and (argvs['-gbid'] or argvs['-gauto']):
        bid,desc=lib_rule.getdesc4cve(rinstan.cve)
        if not rinstan.bid:
            rinstan.bid=bid
        rinstan.edesc=desc
    if rinstan.cve and rinstan.cnnvd=='' and argvs['-gauto']:
        cnnvd=lib_rule.getCNNVD(rinstan.cve)
        rinstan.cnnvd=cnnvd
    if (argvs['-gcnvd'] or argvs['-gauto']) and (rinstan.cnvd=="" and rinstan.msg=="") and rinstan.cve:
        cname,cnvd=lib_rule.getCNVD(rinstan.cve)
        rinstan.cname=cname
        rinstan.cnvd=cnvd
    if (argvs['-gauto'] or argvs['-gversion']) and rinstan.version=="" and rinstan.bid:
        ename,version=lib_rule.getversion4bid(rinstan.bid)
        if rinstan.ename=='':
            rinstan.ename=ename
        rinstan.version=version
    if (argvs['-gauto'] and rinstan.desc=="") or argvs['-gdesc']:
        if rinstan.cnvd:
            cname,desc=lib_rule.getdesc4cnvd(rinstan.cnvd)
            rinstan.desc=desc
            if not rinstan.cname:
                rinstan.cname=cname
        if rinstan.desc=='' and rinstan.edesc:
                rinstan.desc=rinstan.edesc
    if (argvs['-gauto'] or argvs['-gmsg']) and rinstan.msg=="":
        if rinstan.cname:
            rinstan.msg=rinstan.cname
        else:
            rinstan.msg=rinstan.ename
    if argvs['-tran'] or argvs['-gauto']:
        if argvs['-tran'] or (not rinstan.cnvd):
            if rinstan.desc:
                rinstan.desc=lib_rule.transen2zh(rinstan.desc)
            if rinstan.msg:
                rinstan.msg=lib_rule.transen2zh(rinstan.msg)
   
    if argvs['-work']=="2":
        rinstan.output(ofile)
    elif argvs['-work']=="1":
        outdata(rinstan)

if len(sys.argv)<3:
    print "parameter is error,again!!!"
    exit(1)
i=1
while i<len(sys.argv):
    keys=argvs.keys()
    try:
        keys.index(sys.argv[i])
        pl=setparameter(sys.argv[i],i)
        i+=pl
    except Exception:
        print "parameter is error,again!!!"
if argvs['-work']=='1':
    ofile=argvs['-f']+".grule"
elif argvs['-work']=='2':
    ofile=argvs['-f']+".rules"
else:
    print "work model error,again..."
    exit(1)
ofile=open(ofile,'w')
opera(opera_crule)
ofile.close()
print len(gobject)



    


    
