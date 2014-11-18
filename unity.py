import lib_rule
import shutil
import os

def task_1(p='F:\\Work\\rerule\\pkt'):
    os.chdir(p)
    ls=0
    s=18187
    for line in open('357_1.rules'):
        tid,msg=lib_rule.getidmsg4rule(line)
        if os.path.isfile(tid+'.pcap'):
            shutil.move(tid+'.pcap','tmp1/%s.pcap' %(s+ls))
            ls+=1
                        
task_1()                        
                        
                        
                        
            