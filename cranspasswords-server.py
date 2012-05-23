#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""cranspasswords-server.py: Serveur pour cranspasswords"""

import glob
import os
import pwd
import sys
import json

MYUID = pwd.getpwuid(os.getuid())[0]
if MYUID == 'root':
    MYUID = os.environ['SUDO_USER']

KEYS = {
    "aza-vallina": ("Damien.Aza-Vallina@crans.org", None),
    "dandrimont": ("nicolas.dandrimont@crans.org", "66475AAF"),
    "nicolasd": (None, None),
    "blockelet": ("blockelet@crans.org", "AF087A52"),
    "chambart": ("pierre.chambart@crans.org", "F2530FCE"),
    "dimino": ("jdimino@dptinfo.ens-cachan.fr", "2127F85A"),
    "durand-gasselin": ("adg@crans.org", "8E96ACDA"),
    "glondu": ("Stephane.Glondu@crans.org", "49881AD3"),
    "huber": ("olivier.huber@crans.org", "E0DCF376"),
    "lagorce": ("xavier.lagorce@crans.org", "0BF3708E"),
    "parret-freaud": ("parret-freaud@crans.org", "7D980513"),
    "tvincent": ("vincent.thomas@crans.org", "C5C4ACC0"),
    }

ROLES = {
    "bureau": [
        "aza-vallina",
        ],
    "ca": [
        "aza-vallina",
        "blockelet",
        "durand-gasselin",
        "lagorce",
        ],
    "rtc": [
        "dandrimont",
        "nicolasd",
        ],
    "nounou": [
        "blockelet",
        "chambart",
        "dandrimont",
        "dimino",
        "durand-gasselin",
        "glondu",
        "huber",
        "lagorce",
        "parret-freaud",
        "tvincent",
        ],
    }
    
MYDIR = '/var/local/cranspasswords/'
STORE = MYDIR + 'store/'

def validate(roles):
    """Valide que l'appelant appartient bien aux roles précisés"""
    for role in roles:
        if MYUID in ROLES[role]:
            return True
    return False

def getpath(filename):
    """Récupère le chemin du fichier `filename'"""
    return os.path.join(STORE, '%s.json' % filename)

def writefile(filename, contents):
    """Écrit le fichier de manière sécure"""
    os.umask(0077)
    f = open(filename, 'w')
    f.write(contents)
    f.close()

def listroles():
    """Liste des roles existant et de leurs membres"""
    return ROLES

def listkeys():
    """Liste les uid et les clés correspondantes"""
    return KEYS

def listfiles():
    """Liste les fichiers dans l'espace de stockage, et les roles qui peuvent y accéder"""
    os.chdir(STORE)

    filenames = glob.glob('*.json')

    files = {}
    
    for filename in filenames:
        file_dict = json.loads(open(filename).read())
        files[filename[:-5]] = file_dict["roles"]
        
    return files
    
def getfile(filename):
    """Récupère le fichier `filename'"""

    filepath = getpath(filename)
    try:
        return json.loads(open(filepath).read())
    except IOError:
        return False
     

def putfile(filename):
    """Écrit le fichier `filename' avec les données reçues sur stdin."""

    filepath = getpath(filename)
    
    stdin = sys.stdin.read()
    parsed_stdin = json.loads(stdin)

    try:
        roles = parsed_stdin['roles']
        contents = parsed_stdin['contents']
    except KeyError:
        return False

    try:
        oldroles = getfile(filename)['roles']
    except TypeError:
        pass
    else:
        if not validate(oldroles):
            return False
    
    writefile(filepath, json.dumps({'roles': roles, 'contents': contents}))
    return True

def rmfile(filename):
    """Supprime le fichier filename après avoir vérifié les droits sur le fichier"""
    try:
        roles = getfile(filename)['roles']
    except TypeError:
        return True
    else:
        if validate(roles):
            os.remove(getpath(filename))
        else:
            return False
    return True

if __name__ == "__main__":
    argv = sys.argv[1:]
    if len(argv) not in [1, 2]:
        sys.exit(1)
    command = argv[0]
    filename = None
    try:
        filename = argv[1]
    except IndexError:
        pass

    if command == "listroles":
        print json.dumps(listroles())
    elif command == "listkeys":
        print json.dumps(listkeys())
    elif command == "listfiles":
        print json.dumps(listfiles())
    else:
        if not filename:
            sys.exit(1)
        if command == "getfile":
            print json.dumps(getfile(filename))
        elif command == "putfile":
            print json.dumps(putfile(filename))
        elif command == "rmfile":
            print json.dumps(rmfile(filename))
        else:
            sys.exit(1)
    
