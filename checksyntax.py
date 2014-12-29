import os
import sys
import re

def check_topidp(key):
    search=uncompatibility.search(key)
    if search:
        if line[:7] not in ('#TOPIDP','#TOPSEC'):
            printmsg("contain uncompatibility key '%s' of rule that must have #TOPIDP or #TOPSEC in begin" %search.group())


def requireV(v='2.7'):
    if sys.version[:3]!=v:
        print "Please install python v2.7 for this script"
        exit(1)
    
def check(line):
    line=line.strip()
    if len(line)<3:
        return 1
    index_h=line.find('(msg:')
    if index_h<=0:
        printmsg("'(msg' is must,this is a invaild rule")
        return 0
    head=line[:index_h].strip()
    body=line[index_h:].strip()
    return check_head(head)&check_body(body)

def printmsg(msg,tp=0):
    global abnormals
    if tp:
        print "Alert in %d: %s" %(curline,msg)
    else:
        print "Error in %d: %s" %(curline,msg)
    abnormals+=1
    

def syntax_regular(rs):
    bracket_pair=[]
    bracket='{[()]}'
    pair={'}':'{',']':'[',')':'('}
    for i in range(len(rs)):
        if i>32:
            pass
        if (rs[i] in bracket) and ((not i) or rs[i-1]!='\\' ):
            if  bracket_pair and (rs[i] in bracket[3:]) and bracket_pair[-1]==pair[rs[i]]:
                bracket_pair.pop()
            else:
                bracket_pair.append(rs[i])
    if len(bracket_pair):
        printmsg("regular expression syntax error")
        if model&1:
            print bracket_pair
        return 0
    return 1

cvt=""
def syntax_pcre(rs):
    match=re_pcre.match(rs)
    if not match:
        printmsg("pcre: struct error")
        return 0
    ps=match.groups()[0]
    
    for i in range(len(ps)):
        if ps[i]=='/':
            if i==0:
                printmsg("pcre: / must transform  to \\/ in %d" %i)
            
            elif i>0 and ps[i-1]!='\\':
                printmsg("pcre: / must transform  to \\/")
        if i>0 and ps[i-1]=='\\':
            if ps[i] not in cvt:
                printmsg("pcre: %s have unnecessary \\ in %d" %(ps[i],i))
        
    if model&2:
        try:
            re.compile(match.groups()[0])
        except Exception:
            return syntax_regular(match.groups()[0])
    else:
        return 1
    
def syntax_msg(rs):
    if rs[1]==' ' or rs[-2]==' ':
        printmsg("msg: must have no blank in msg value")
        return 0
    else:
        return 1

def syntax_content(rs):
    num=0
    rhex=re.compile(r'^([\dABCDEF]{2} )*[\dABCDEF]{2}$',re.I)
    d1=rs.find('"')
    d2=rs.rfind('"')
    v=rs[d1+1:d2]
    for i in v:
        if i in (':',';','"','\\'):
            printmsg("(uri)content: must have not \\  : ; \" in value")
            return 0
    while num<len(v):
        a=v.find('|',num)
        b=v.find('|',a+1)
        if a>=0 and b>=0:
            v=v[a+1:b]
            if rhex.match(v):
                num=b+1
                continue
            else:
                printmsg("content: |hex| format is wrong")
                return 0
        else:
            return 1
    return 1


def getregular(res):
    res=res.strip()
    i=res.find('/')
    j=res.find('/',i+1)
    if j>i>=0:
        return res[i+1:j]
    return None

def keysyntax(path):
    global uncompatibility
    global cvt
    path=path+'\\key.syn'
    #path=""
    try:
        f=open(path)
        keys={}
        if not f:
            print "Error: Open syntax file fail"
            return None
    except Exception:
        print "Error: The syntax is not exist"
        return None
    
    for line in f:
        line=line.strip()
        if (not line) or line[0]=='#' :
            continue
        lt=line.split(' ',1)
        if len(lt)==1:
            keys[lt[0]]=None
            continue
        key=lt[0]
        if key=="@uncompatibility":
            if 'uncompatibility' in globals():
                uncompatibility=re.compile(lt[1].strip())
            continue
        if key=='@cvt':
            cvt=lt[1]
            continue
        regular=getregular(lt[1])
        if not regular:
            print line,':syntax file error'
            return None
        try:
            keys[key]=re.compile(regular)#,re.I)
        except Exception:
            print line,':syntax file error'
            return None
    return keys

def check_head(head):
    try:
        re_head=keys['head']
    except KeyError:
        print "loss the syntax for head of rule,please edit key.syn"
        sys.exit()
    match=re_head.search(head)
    
    if not match:
        printmsg("this is a invaild rule head")
        return 0        
    #print match.groups()
    return 1

def check_body(body):
    i=1
    cur=1
    if body[-2:]!=';)':
        printmsg("';)' is must,invaild rule body,loss right bracket or have blank at %d" %(len(body)-2))
        return 0
    while i<len(body):
        if body[i]==';':
            key=body[cur:i].strip()
            if key=='':
                break
            if model&1:
                print key
            try:
                keys[key]
                if model&8:
                    check_topidp(key)                
                if body[i-1]==' ':
                    printmsg(key+"::have nonecessary blank before semicolon at %d" %i) #must no blank before semicolon
                    
                if (body[i+1]!=' ' or body[i+2]==' ') and body[i+1]!=')':
                    printmsg(key+'::after this key must have one blank only at %d' %i) #have one blank after key
                    #return 0
                i=i+1
                cur=i         
                continue
            except KeyError:
                printmsg(key+"::nonexist this keyword at %d" %cur)
                return 0
            
            
        if body[i]==':':
            key=body[cur:i].strip()
            if model&1:
                print key,
            if model&8:
                check_topidp(key)            
            try:
                j=i+1
                while 1:
                    j=body.find(';',j)
                    if j>0 and body[j-1]=='\\':
                        j+=1
                        continue
                    break
                
                if j<0:
                    #if key!='rev':
                    printmsg(key+"::loss semicolon at %d" %j)
                    return 0
                
                rs=body[i+1:j]#.strip()
                
                if (model&4) and (len(rs.strip())<len(rs)):
                    printmsg(key+"::the vaule for the key have nonecessary blank at %d" %j) #key value have no blank at hean and end
                    
                if model&1:
                    print rs              

                ree=keys[key]
                if ree and (not ree.match(rs)):
                    printmsg(key+'::syntax error or have blank at %d' %j) #check syntax form key.syn
                    return 0
                try:
                    if (body[j+1]!=' ' or body[j+2]==' ') and body[j+1]!=')':
                        printmsg(key+'::after this key must have one blank only at %d' %j) #have one blank after key
                        #return 0
                except IndexError:
                    pass
                
                if key in syntax_builtin.keys():
                    if not syntax_builtin[key](rs):
                        return 0                
                if j<0:
                    break
                i=j+1
                cur=i
                continue
            except KeyError:
                printmsg(key+"::nonexist this keyword at %d" %cur)
                return 0
        i+=1
    return 1

#re_head=re.compile(r'^ *(alert|drop|log|pass|activate) +(tcp|udp|ip|icmp) +(any|[!\d\.]+|\x24.+) +(any|[!\[\]:,\d]+|\x24.+) +(->|<-|<>) +(any|[!\d\.]+|\x24.+) +(any|[!\[\]:,\d]+|\x24.+) *$',re.I)

keys=None
syntax_builtin={'pcre':syntax_pcre,'content':syntax_content,'uricontent':syntax_content,'msg':syntax_msg}
#re_content=re.compile(r'!? *\".*\"')
#re_msg=re.compile(r'\".*\"')
re_pcre=re.compile(r'!? *\"/(.*)/[ismxAEGRUBPHMCOIDKYS]*\"')
curline=0

if len(sys.argv)<2:
    print "-------------------------"
    print "Author: Guo Guisheng"
    print "Date: 2014/12/23"
    print "Version:3.3"
    print "User: checksyntax.py path mode"
    print "path1: The path of file for rule"
    print "mode : They are could be '-drsi' "
    print "d: debug model "
    print "r: strict check for regular syntax"
    print "s: strict check for key value"
    print "i: check can't compatibility key whether have #TOPIDP in first line"
    print "-------------------------"
    sys.exit()

requireV()
model=0
if len(sys.argv)>=3:
    if sys.argv[2][0]!='-':
        print "paramter error,again!!!"
        sys.exit()
    if 'd' in sys.argv[2]:
        model=model|1
    if 'r' in sys.argv[2]:
        model=model|2
    if 's' in sys.argv[2]:
        model=model|4
    if 'i' in sys.argv[2]:
        model=model|8
        uncompatibility=None
path=sys.argv[1]
stxpath=os.path.split(sys.argv[0])[0]
if not os.path.isfile(path):
    print "this file is invaild,again!!"
    sys.exit()
f=open(path)
rules=0
abnormals=0
keys=keysyntax(stxpath)
if not keys:
    sys.exit()
for line in f:
    curline+=1
    if line[0]=='#' and line[1:4]!="TOP":
        continue
    rules+=1
    if model&1:
        print "==================================="
    check(line)
    #    abnormals+=1

print "===================================="
print "lines of number is: %d" %curline
print "check number of rules: %d" %rules
print "number of abnormal rules: %d" %abnormals
print "====================================="


