import os
import sys
import lib_rule
if len(sys.argv)<3:
    print "USE: rule tid"
    print "tid: tid file or tid dir"
    exit(1)
if os.path.isdir(sys.argv[2]):
    tids=lib_rule.gettid4dir(sys.argv[2])
elif os.path.isfile(sys.argv[2]):
    tids=lib_rule.gettid4file(sys.argv[2])
    
grs=lib_rule.getinfo4rule(sys.argv[1],1)

print "load tid: %d" %len(tids)
print "load rule: %d" %len(grs)
print "====================================================="
for tid in tids:
    try:
        print grs[tid][1]
    except Exception:
        print "#have no rules for tid %s" %tid
