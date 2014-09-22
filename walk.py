import os


def filter(fname):
    f=open(fname,'rb')
    if f.read(4)=='\xd4\xc3\xb2\xa1':
        f.close()
        return 1
    else:
        f.close()
        return 0
    
def getpcaplist_2(path):
    flist=[]
    blist=[]
    wl=os.walk(path)
    for i in wl:
        for j in i[2]:
            if ispcap(j)==1:
                fname=i[0]+"\\"+j
                if filter(fname):
                    flist.append(fname)
                else:
                    blist.append(fname)
    return flist,blist

def getpcaplist(path):
    flist=os.listdir(path)
    pcaplist=[]
    for i in flist:
        p1=path+"/"+i
        if os.path.isfile(p1):
            if ispcap(p1):
                pcaplist.append(p1)
                
        elif os.path.isdir(p1):
            plist=getpcap(p1)
            for j in plist:
                p2=p1+"/"+j
                pcaplist.append(p2)
    return pcaplist

extlt=('.pcap','.cap')
def ispcap(fname):
    ext=os.path.splitext(fname)[1]
    try:
        extlt.index(ext)
        return 1
    except Exception:
        return 0
    
def test(path):
    if not os.path.isdir(path):
        return
    os.chdir(path)
    pcaplist,bpcaplist=getpcaplist_2(path)
    f=open("pcap.list",'w')
    for i in pcaplist:
        f.write(i+"\n")
    f.close()
    f=open('bpcap.list','w')
    for i in bpcaplist:
        f.write(i+"\n")
    f.close()    

