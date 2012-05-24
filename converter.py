#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import json
import glob
import os,sys
# Basic converter to json, avec roles nounous partout

init_path = '/home/dstan/crans/passwords/'
final_path = '/home/dstan/crans/passwords/v2/'

os.chdir(init_path)

filenames = glob.glob('*.asc')

encoder=json.JSONEncoder()
for filename in filenames:
    fname=final_path+filename[:-4]+'.json'
    if os.path.exists(fname):
        print "%s already exists, ignored" % filename
        continue
    else:
        print "Traitement de %s" % filename
    nf = file(fname,'w')
    
    nf.write(encoder.encode({'roles':['nounous']\
        ,'contents':open(filename).read()}))
        
