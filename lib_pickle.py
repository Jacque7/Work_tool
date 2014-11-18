import pickle

def get4file(path):
    pkl_file = open(path, 'rb')
    data = pickle.load(pkl_file)
    pkl_file.close()
    return data

def dump2file(path,obj,type=None):
    output = open(path, 'wb')
    pickle.dump(obj, output,type) 
    output.close()
    
def dict2txt(path,obj):
    output=open(path,'w')
    for k,v in obj.items():
        v=','.join(v)
        output.write(k+','+v+'\n')
    output.close()
    
"""    
def dump2txt(path,obj):
    f=open(path,'w')
    for i in obj:
        print(i,file=f)
    f.close()
"""