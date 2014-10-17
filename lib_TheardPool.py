import threading
import sys
import time
import Queue
########################################################################
class threadpool(threading.Thread):

    #----------------------------------------------------------------------
    def __init__(self,tmax=20,invrt=1,overact=None,start=True):
        threading.Thread.__init__(self)
        self.queue=Queue.Queue()
        self.threads=[None]*tmax
        self.tmax=tmax
        self.invrt=invrt
        self.overact=overact
        if start:
            self.start()
        
    def run(self):
        while True:
            try:
                func,args=self.queue.get(timeout=1)
                slot=self.getthreadslot()
                self.starttask(slot,func,args)
            except Queue.Empty:
                print "\nThread Pool is empty"
                print "Wait subthread complete..."
                self.waitcomplete()
                if self.overact:
                    self.overact[0](self.overact[1])
                exit(0)
                #return
        
            
    def getthreadslot(self):
        while True:
            for i in range(self.tmax):
                if not isinstance(self.threads[i],threading.Thread):
                    return i
                if not self.threads[i].isAlive():
                    return i
            time.sleep(self.invrt)
            
    def starttask(self,slot,func,args):
        self.threads[slot]=threading.Thread(target=func,args=args)
        self.threads[slot].start()
        #print self.threads[slot].getName()[7:],
        print "=",
    def addtask(self,func,args):
        self.queue.put((func,args))
    
    def waitcomplete(self):
        for t in self.threads:
            if isinstance(t,threading.Thread) and t.isAlive():
                t.join()
                    
        
                
            
                
        
        
        
        
        
    
    