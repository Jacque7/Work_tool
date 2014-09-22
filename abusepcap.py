import os
import sys
import time
########################################################################
class offlinepf:
    def __init__(self,name):
        """Constructor"""
        self.name=name
        self.hfile=open(name,'rb')
        self.type=self.getype()
        self.struct={"tcpdump":{'head':0x18,'packet':16,'time':(0,8),'caplen':(8,4),'pktlen':(12,4)},\
                     'na_2':{'head':0x80,'packet':0x28,'caplen':(8,2),'pktlen':(10,2)},\
                     'msntmon_1':{'head':0x80,'packet':8,'caplen':(4,2),'pktlen':(6,2),'end':'\x80\x00\x00\x00\xc4\x00\x00x00'},\
                     'msntmon_2':{'head':0x80,'packet':16,'caplen':(8,4),'pktlen':(12,4),'end':'\x80\x00\x00\x00\xcc\x00\x00x00'},\
                     'pcapng_1':{'head':0x2a,'packet':0x22,'caplen':(0x1a,4),'pktlen':(0x1e,4),'end':'\x00\x00\x58\x00\x00\x00'},\
                     'pcapng_2':{'head':0x38,'packet':0x20,'caplen':(0x18,4),'pktlen':(0x1c,4),'end':'\x5c\x00\x00\x00'}}
        
    def getype(self):
        #\xa1\xb2\xc3\xd4
        magic=self.hfile.read(4)
        if magic=='\xD4\xC3\xB2\xA1':
            return 'tcpdump'
        if magic=='\x0a\x0d\x0d\x0a':
            self.hfile.seek(0x20)
            c=self.hfile.read(1)
            if c=='\x20':
                return 'pcapng_2'
            else:
                return 'pcapng_1'
        if magic=='\x52\x54\x53\x53':
            return 'msntmon_1'
        if magic=='\x58\x43\x50\x00':
            return 'na_2'
        if magic=='\x47\x4d\x42\x55':
            return 'msntmon_2'
        return None
    def getinfo4pks(self,pks,ts):
        nums=self.struct[self.type].get(ts)
        if nums:
            return pks[nums[0]:nums[0]+nums[1]]
        return None
    
    def getdata(self,caplen):
        s=""
        lenght=len(caplen)-1
        for i in range(lenght,-1,-1):
            s+=caplen[i]
        lenght=int(s.encode('hex'),16)
        data=self.hfile.read(lenght)
        return data
    
    def packetloop(self,func):
        ftype=self.type
        self.hfile.seek(self.struct[ftype]['head'])
        while 1:
            pks=self.hfile.read(self.struct[ftype]['packet'])
            if not pks:
                return
            if len(pks)<self.struct[ftype]['packet']:
                return
            if ftype[:4]=='msnt' and self.struct[ftype].get('end') and pks[:len(self.struct[ftype]['end'])]==self.struct[ftype]['end']:
                return
            time=self.getinfo4pks(pks,'time')
            pktlen=self.getinfo4pks(pks,'pktlen')
            caplen=self.getinfo4pks(pks,'caplen')
            data=self.getdata(caplen)
            func({'time':time,'pktlen':pktlen,'caplen':caplen,'data':data})


def getpktime():
    global now
    s=hex(now)[2:].decode('hex')
    time=""
    for i in range(3,-1,-1):
        time+=s[i]
    now+=1
    return time+"\x00"*4

def writedown(dt):
    global fw,now
    caplen=dt['caplen']
    caplen+='\x00'*(4-len(caplen))
    pktlen=caplen
    time=getpktime()
    fw.write(time+caplen+pktlen+dt['data'])

fw=None
now=None
head='\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x01\x00\x00\x00'
def abuse2pcap(src):
    global fw,now
    if not os.path.exists(src):
        print "error:",src
        return
    name,ext=os.path.splitext(src)
    obj=offlinepf(src)
    if not obj.type:
        return src
    fname=name+'_cvt.pcap'
    fw=open(fname,'wb')
    now=int(time.time())
    fw.write(head)
    obj.packetloop(writedown)
    fw.close()
    return fname

f=open('f:/packet/bpcap.list')
ff=open('f:/packet/gpcap.list','w')
for line in f:#abuse2pcap('f:/p.cap
    line=line[:-1]
    if not os.path.exists(line):
        continue
    name=abuse2pcap(line)
    print name
    ff.write(name+'\n')

    

    