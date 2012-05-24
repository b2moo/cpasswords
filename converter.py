import json
import glob
import os
# Basic converter to json, avec roles nounous partout

init_path = '/home/dstan/crans/passwords/'
final_path = '/home/dstan/crans/passwords/v2/'

os.chdir(init_path)

filenames = glob.glob('*.asc')

encoder=json.JSONEncoder()
for filename in filenames:
    nf = file(final_path+filename[:-4]+'.json','w')
    
    nf.write(encoder.encode({'roles':['nounous']\
        ,'contents':open(filename).read()}))
        
