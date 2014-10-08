import sys
import os
import time
import threading
########################################################################
class threadpool:
    """
    thread pool,easy for manager multithreading
    
    """
    #----------------------------------------------------------------------
    def __init__(self,func=None,tmax=10,interval=1):
        self.func=func #default thread function
        self.tmax=tmax
        self.tpool=[]
        self.tlist=[]
        self.interval=interval
        
    def setdefaultfunc(self,func):
        print type(setdefaultfunc)
        if func:
            self.func=func
    
    def addtask(self,args,func=None):
        self.pool.append((args,func))
        return len(self.pool)
    
    def startask(self):
        if not self.tpool:
            print "have no task in pool"
            return
        print "Have %d task in the thread pool,it's start to work......"
        self.startime=time.time()
        for i in range(min(self.tmax,len(self.tpool))):
            targs,tfunc=self.tpool.pop(0)
            if not tfunc:
                tfunc=self.func
            self.tlist.append(threading.Thread(target=tfunc,args=targs))
            self.tlist[i].start()
        
        while self.tpool:
            time.sleep(self.interval)
            for i in range(len(self.tlist)):
                if not self.tlist[i].isAlive():
                    targs,tfunc=self.tpool.pop(0)
                    if not tfunc:
                        tfunc=self.func
                    self.tlist[i]=threading.Thread(target=tfunc,args=targs)
                    self.tlist[i].start()
                        
    def isADead(self):
        for thread in self.tlist:
            if thread.isAlive():
                return False
        return True
    
    def waitcomplete(self):
        self.startask()
        while True:
            time.sleep(1)
            if self.isADead():
                return time.time()-self.startime
    
            
        
            
    
            
        
        
    
    