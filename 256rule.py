import os
import sys
import lib_rule
import re
import random

risk={'2003':'9','4001':'2','4002':'5','4003':'1','5001':'3','6001':'7',\
      '6002':'7','6003':'6','8001':'8','8002':'8','1001':'3','1101':'4',\
      '1111':'4','2222':'5'}
cid=1000
flows={}

def geti4line(line,ln=0):
    a=line.rfind('@')
    b=line.rfind(')')
    if a<0 or b<0 or a<=b:
        if ln>0:
            print "Have no info in %d" %ln
        return
    rule=line[:a].strip()
    info=line[a+1:].strip()
    i=info.rfind(' ')
    name=info[:i]
    gid=info[i+1:]
    return rule,name,gid

def getdirection(prule):
    pt1=prule['head'][4]
    pt2=prule['head'][7]
    dire=prule['head'][5]
    if pt1==pt2=='any':
        return '1'
    if pt2!='any' and (dire=='->' or dire=='<>'):
        return '1'
    return '2'

def cvtprule(prule,name,gid,level,r,dt,cid,fb):
    bodys=""
    for i in prule['body']:
        if isinstance(i,tuple):
            if i[0]=='msg':
                bodys+="(msg:\"%s - %s\"; " %(name,i[1][1:-1])
            elif i[0]=='tid':
                bodys+="%s:%s; " %(i[0],i[1])
                bodys+="gid:%s; " %gid
                bodys+="sid:260804%s%02d; " %(cid,fb)
            elif i[0]=='rev':
                bodys+='rev:%s%s%s;)' %(dt,level,r)
            else:
                bodys+="%s:%s; " %(i[0],i[1])
        else:
            bodys+="%s; " %i
            
    return bodys
                                           
def rule256(prule,name,gid,flow):
    global cid
    level=79+random.randint(-20,20)
    r=risk[gid]
    dt=getdirection(prule)
    try:
        head=' '.join(prule['head'])
    except TypeError:
        head=' '.join(prule['head'][1:])
    if flow==-1:
        cid+=1
    if flow<0:flow=0
    body=cvtprule(prule,name,gid,level,r,dt,cid,flow)
    out.write(head+" "+body+'\n')

  
i=1
rflowbit=re.compile(r'flowbits: *(is)?set *, *(\w*) *;')
pp=os.path.split(sys.argv[1])
out=open(pp[0]+'/'+pp[1]+'.56rules','w')
err=open(pp[0]+'/err.log','a+')

for line in open(sys.argv[1]):
    rs=geti4line(line,i)
    if rs:
        m=rflowbit.search(rs[0])
        if m:
            k=m.groups()[1]
            if flows.get(k):
                flows[k].append(line.strip())
            else:
                flows[k]=[line.strip()]
            i+=1
            continue
        prule=lib_rule.parserule(rs[0],i)
        rule256(prule,rs[1],rs[2],-1)
        i+=1
        

for k,lines in flows.items():
    if len(lines)<2:
        err.write(lines[0]+'\n')
        continue
    cid+=1
    for l in range(len(lines)):
        rs=geti4line(lines[l])
        prule=lib_rule.parserule(rs[0])
        rule256(prule,rs[1],rs[2],l)    