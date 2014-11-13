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
"""    
def dump2txt(path,obj):
    f=open(path,'w')
    for i in obj:
        print(i,file=f)
    f.close()
"""