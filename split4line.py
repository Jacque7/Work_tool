import os
import sys

if len(sys.argv)<2:
    print "split4line file nums"
    print "please again"
    exit(1)
if not os.path.isfile(sys.argv[1]):
    print "please entry vaild file"
    exit(1)
    
st=25
if len(sys.argv)>=3:
    if sys.argv[2].isdigit():
        st=int(sys.argv[2])
    else:
        print "please entry vaild nums"
        exit(1)
d,f=os.path.split(sys.argv[1])
os.chdir(d)
fnum=1
fline=0
fp=open(f)
for line in fp:
    if not fline%25:
        try:
            fw.close()
        except Exception:
            pass
        fw=open(str(fnum)+'.rules','w')
        fnum+=1
    fw.write(line)
    fline+=1
fw.close()