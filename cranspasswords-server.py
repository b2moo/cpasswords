#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""cranspasswords-server.py: Serveur pour cranspasswords"""

MYDIR = '/home/dstan/cranspasswords/'
STORE = MYDIR+'test/'

import glob
import os
import pwd
import sys
import json
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

MYUID = pwd.getpwuid(os.getuid())[0]
if MYUID == 'root':
    MYUID = os.environ['SUDO_USER']

CRANSP_MAIL = "root@crans.org"
DEST_MAIL = "dstan@crans.org"

KEYS = {
    "aza-vallina": ("Damien.Aza-Vallina@crans.org", None),
    "dandrimont": ("nicolas.dandrimont@crans.org", "66475AAF"),
    "blockelet": ("blockelet@crans.org", "AF087A52"),
    "chambart": ("pierre.chambart@crans.org", "F2530FCE"),
    "dimino": ("jdimino@dptinfo.ens-cachan.fr", "2127F85A"),
    "durand-gasselin": ("adg@crans.org", "8E96ACDA"),
    "glondu": ("Stephane.Glondu@crans.org", "49881AD3"),
    "huber": ("olivier.huber@crans.org", "E0DCF376"),
    "lagorce": ("xavier.lagorce@crans.org", "0BF3708E"),
    "parret-freaud": ("parret-freaud@crans.org", "7D980513"),
    "tvincent": ("vincent.thomas@crans.org", "C5C4ACC0"),
    "iffrig": ("iffrig@crans.org","5BEC9A2F"),
    "becue": ("becue@crans.org", "194974E2"),
    "dstan": ("daniel.stan@crans.org", "6E1C820B"),
    "samir": ("samir@crans.org", "41C2B76B"),
    "boilard": ("boilard@crans.org", "C39EB6F4"),
    "cauderlier": ("cauderlier@crans.org",None),    #Méchant pas beau
    "maioli": ("maioli@crans.org",None)             #Bis (maybe 9E5026E8)
    }

RTC=[
    "dandrimont",
    "iffrig"
    ]
NOUNOUS=RTC+[
    "blockelet",
    "becue",
    "dstan",
    "chambart",
    "dimino",
    "durand-gasselin",
    "glondu",
    "huber",
    "lagorce",
    "parret-freaud",
    "cauderlier",
    "maioli",
    "samir",
    "boilard"
    ]

CA=["becue","dstan","boilard"]

ROLES = {
    "ca": CA,
    "ca-w": CA,
    "nounous": NOUNOUS,
    "nounous-w": NOUNOUS #Or maybe RTC ?
    }


def validate(roles,mode='r'):
    """Valide que l'appelant appartient bien aux roles précisés
    Si mode mode='w', recherche un rôle en écriture
    """
    for role in roles:
        if mode == 'w': role+='-w'
        if ROLES.has_key(role) and MYUID in ROLES[role]:
            return True
    return False

def getpath(filename,backup=False):
    """Récupère le chemin du fichier `filename'"""
    return os.path.join(STORE, '%s.%s' % (filename,'bak' if backup else 'json'))

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
        old = getfile(filename)
        oldroles = old['roles']
    except TypeError:
        old = "[Création du fichier]"
        pass
    else:
        if not validate(oldroles,'w'):
            return False
    
    notification("Modification de %s" % filename,\
    "Le fichier %s a été modifié par %s." %\
        (filename,MYUID),filename,old)


    writefile(filepath, json.dumps({'roles': roles, 'contents': contents}))
    return True

def rmfile(filename):
    """Supprime le fichier filename après avoir vérifié les droits sur le fichier"""
    try:
        old = getfile(filename)
        roles = old['roles']
    except TypeError:
        return True
    else:
        if validate(roles,'w'):
            notification("Suppression de %s" % filename,\
                "Le fichier %s a été supprimé par %s." %\
                (filename,MYUID),filename,old)
            os.remove(getpath(filename))
        else:
            return False
    return True

def notification(subject,corps,fname,old):
    back = open(getpath(fname,True),'a')
    back.write(json.dumps(old))
    back.write('\n')
    back.write('* %s: %s\n' % (str(datetime.datetime.now()),corps)) 
    back.close()

    # Puis envoi du message
    conn = smtplib.SMTP('localhost')
    frommail = CRANSP_MAIL
    tomail = DEST_MAIL
    msg = MIMEMultipart(_charset="utf-8")
    msg['Subject'] = subject
    # me == the sender's email address
    # family = the list of all recipients' email addresses
    msg['From'] = "cranspasswords <%s>" % CRANSP_MAIL
    msg['To'] = DEST_MAIL
    msg.preamble = "cranspasswords report"
    info = MIMEText(corps + 
        "\nLa précédente version a été sauvegardée" +
        #"\nCi-joint l'ancien fichier." +
        "\n\n-- \nCranspasswords.py",_charset="utf-8")
    msg.attach(info)
    #old = MIMEText(old)
    #old.add_header('Content-Disposition', 'attachment', filename=fname) 
    #msg.attach(str(old))
    conn.sendmail(frommail,tomail,msg.as_string())
    conn.quit()

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
    
