import win32com.client
import os
import shutil
class accessdb:
    def __init__(self,dbpath,dbpw='admin'):
        self.dbpath=dbpath
        #self.dbname=dbname
        self.dbqw=dbpw
        self.db='Provider=Microsoft.Jet.OLEDB.4.0;Persist Security Info=False;Data Source=%s' % (dbpath)
        self.conn=win32com.client.Dispatch('ADODB.Connection')
        self.conn.Open(self.db)
        self.rs=win32com.client.Dispatch('ADODB.Recordset')        
        
    def executesql(self,sql):
        self.rs.Open('['+sql+']',self.conn,1,3)
        #self.rs.MoveFirst()
        #while not self.rs.EOF:
        info=self.rs.GetRows(1)
        #self.rs.MoveNext()
        self.rs.Close()
        d=(str(info[0][0])+'.pcap',info[1][0],str(info[0][0]))
        if info[2][0]:
            return ';'.join(d)+';'+info[2][0].replace('\n','')
        else:
            return ';'.join(d)+';'
        
    def close(self):
        self.conn.Close()

table='vinfo'
title='msg'
tid='TID'
cve='CVE'
#pth=raw_input("Enter the dbpath:")
#nam=raw_input("Enter the dbname:")
pth='F:/Packet/execl/2014_08_18/ips-v2014.08.18.mdb' # rule db
mysql="select %s,%s,%s from %s where %s=" %(tid,title,cve,table,tid) # tid title cve
db=accessdb(pth)
os.chdir('F:/Packet/execl/2014_08_18') # dir for packet
f=open('F:/Packet/execl/2014_08_18/457.txt') # tid file
fw=open('F:/Packet/execl/2014_08_18/stat.csv','w') #out stat file
try:
    os.mkdir('pkt')
except Exception:
    pass
num=1
for line in f:
    line=line.strip()
    name=line+'.pcap'
    vid=line
    if os.path.isfile('packet/'+name):
        info=db.executesql(mysql+vid)+'\n'
        info=info.encode('gbk')
        print info,num
        num+=1
        fw.write(info)
        try:
            #os.mkdir('pkt/'+line[:-5])
            shutil.copy('packet/'+name,'pkt/'+name)
        except Exception:
            pass
        continue
    print line
f.close()
db.close()
