import os
import sys
import lib_pickle
import regule
import shutil
def cast_info_rule(rulelist,infodict,flag=0):
    for rule in rulelist:
        values=infodict.pop(rule.meta[flag]['tid'])
        rule.meta[flag]['precise']=values[0]
        rule.meta[flag]['pop']=values[1]
        rule.meta[flag]['risk']=values[2]
        rule.meta[flag]['os']=values[4]
        rule.meta[flag]['block']=values[5]
        rule.meta[flag]['ttype']=values[3]
        rule.meta[flag]['bid']=values[7]
        rule.meta[flag]['cve']=values[8]
        rule.meta[flag]['atype']=values[9]
        rule.meta[flag]['desc']=values[10]
        rule.meta[flag]['version']=values[11]
        rule.meta[flag]['solve']=values[12]
        rule.meta[flag]['see']=values[13]
        rule.meta[flag]['ename']=values[14]
        rule.meta[flag]['cnnvd']=values[15]
        rule.meta[flag]['cnvd']=values[16]
    
        
def cast_debug_release(d_rulelist,r_rulelist):
    print len(d_rulelist),len(r_rulelist)
    allrule=d_rulelist
    flag=0
    for i in range(len(r_rulelist)):
        #print i
        for j in range(len(d_rulelist)):
            if r_rulelist[i]==d_rulelist[j]:
                allrule[j].meta[1]=r_rulelist[i].meta[1]
                allrule[j].flag=2
                flag=1
                continue
        if not flag:
            r_rulelist
            allrule.append(r_rulelist[i])
            #print len(allrule)
            flag=0
        else:
            flag=0
    
    print len(allrule)
    return allrule

def dumpnewrule(allrulelist,frule=None,finfo=None,flag=0):
    frule=open(frule,'w')
    finfo=open(finfo,'w')
    for rule in allrulelist:
        if flag==1 and rule.flag==0:
            continue
        srule=rule.getrule(flag)
        if srule:
            frule.write(srule+'\n')
        else:
            print rule.meta.tid
        rule.writeinfo(finfo,flag)
    finfo.write('@====================')
    for i in range(1,28):
        frule.write('%d: "' %i)
        for rule in allrulelist:
            if flag==1 and rule.flag==0:
                continue
            eventype=rule.getinfo('eventype')
            if not eventype:
                continue
            if i in eventype:
                frule.write(str(rule.tid)+':1',)
        frule.write('"\n')
    for i in range(len(allrulelist)):
        if not allrulelist[i].getinfo('eventype'):
            print 'noevent',i,rule.getrule()
    
def relen(allrule):
    a=0
    b=0
    c=0
    for rule in allrule:
        f=rule.flag
        if f==0:
            a+=1
        elif f==1:
            b+=1
        elif f==2:
            c+=1
    print a,b,c

def setdrule(rulelist):
    rlist=[]
    for rule in rulelist:
        for r in rlist:
            if rule==r:
                continue
        rlist.append(rule)
    print len(rulelist),len(rlist)
    return rlist
def mapoldnew(alllist,outfile='tidmap.txt'):
    outfile=open(outfile,'w')
    outfile.write('MSG\tTID\tOLD_DEBUG\tOLD_RELEASE\n')
    for rule in alllist:
        if rule.meta[0]['tid']:
            tids="%s\t%s\td:%s" %(rule.getinfo('msg'),rule.tid,rule.meta[0]['tid'])
        else:
            tids="%s\t%s\tNONE" %(rule.getinfo('msg'),rule.tid)
        if rule.meta[1]['tid']:
            tids+='\tr:%s\n' %rule.meta[1]['tid']
        else:
            tids+='\tNONE\n' 
        outfile.write(tids)
    outfile.close()
def mvpkt(alllist,p='F:\\Work\\rerule\\pkt'):
    os.chdir(p)
    for rule in allrule:
        dtid=rule.meta[0]['tid']
        rtid=rule.meta[1]['tid']
        if dtid:
            if os.path.isfile(dtid+'.pcap'):
                if rtid:
                    shutil.move(dtid+'.pcap','release/%s.pcap' %rule.tid)
                else:
                    shutil.move(dtid+'.pcap','debug/%s.pcap' %rule.tid)
        
    
'''
r_rulelist=regule.anasis("F:\\Work\\rerule\\release\\ips-v2014.11.12.rules",1)
#r_rulelist=setdrule(r_rulelist)
d_rulelist=regule.anasis("F:\\Work\\rerule\\debug\\ips-v2014.10.09.rules")
#d_rulelist=setdrule(d_rulelist)

r_infodict=regule.getinfo4table('re_release.txt')
d_infodict=regule.getinfo4table('re_debug.txt')

cast_info_rule(r_rulelist,r_infodict,1)
cast_info_rule(d_rulelist,d_infodict)

lib_pickle.dump2file('r_rulelist.pkl',r_rulelist)
lib_pickle.dump2file('d_rulelist.pkl',d_rulelist)

print len(d_infodict),len(r_infodict)
lib_pickle.dict2txt('r_overinfo.txt',r_infodict)
lib_pickle.dict2txt('d_overinfo.txt',d_infodict)
'''
#d_rulelist=lib_pickle.get4file('d_rulelist.pkl')
#r_rulelist=lib_pickle.get4file('r_rulelist.pkl')
allrule=lib_pickle.get4file('all_rulelist.pkl')
#mapoldnew(allrule)
mvpkt(allrule)
#print len(d_rulelist),len(r_rulelist),len(allrule)
'''
allrule=cast_debug_release(d_rulelist,r_rulelist)
for i in range(len(allrule)):
    allrule[i].tid=10000+i


dumpnewrule(allrule,'debug_ips.rules','debug_info.txt')
dumpnewrule(allrule,'release_ips.rules','release_info.txt',1)


lib_pickle.dump2file('all_rulelist.pkl',allrule)
relen(allrule)


d_infodict=lib_pickle.get4file('d_overinfo.pkl')
r_infodict=lib_pickle.get4file('r_overinfo.pkl')
d_rulelist=lib_pickle.get4file('d_rulelist.pkl')
r_rulelist=lib_pickle.get4file('r_rulelist.pkl')
print r_rulelist[1]
'''


        
        
            
        
        
            