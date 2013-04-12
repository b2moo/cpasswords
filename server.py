#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""Serveur pour cranspasswords"""

import glob
import os
import pwd
import sys
import json
import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from serverconfig import READONLY, CRANSP_MAIL, DEST_MAIL, KEYS, ROLES, STORE

MYUID = pwd.getpwuid(os.getuid())[0]
if MYUID == 'root':
    MYUID = os.environ['SUDO_USER']

def validate(roles, mode='r'):
    """Vérifie que l'appelant appartient bien aux roles précisés
    Si mode mode='w', recherche un rôle en écriture
    """
    for role in roles:
        if mode == 'w':
            role += '-w'
        if ROLES.has_key(role) and MYUID in ROLES[role]:
            return True
    return False

def getpath(filename, backup=False):
    """Récupère le chemin du fichier ``filename``"""
    return os.path.join(STORE, '%s.%s' % (filename, 'bak' if backup else 'json'))

def writefile(filename, contents):
    """Écrit le fichier avec les bons droits UNIX"""
    os.umask(0077)
    f = open(filename, 'w')
    f.write(contents)
    f.close()

def listroles():
    """Liste des roles existant et de leurs membres"""
    return ROLES

def listkeys():
    """Liste les usernames et les (mail, fingerprint) correspondants"""
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
    """Récupère le fichier ``filename``"""
    filepath = getpath(filename)
    try:
        obj = json.loads(open(filepath).read())
        if not validate(obj['roles']):
	        return False
        return obj
    except IOError:
        return False
     

def putfile(filename):
    """Écrit le fichier ``filename`` avec les données reçues sur stdin."""
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
    
        backup(filename, old)
        notification(u"Modification de %s" % filename,
            u"Le fichier %s a été modifié par %s." % (filename, MYUID),
            filename, old)
    
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
            backup(filename, old)
            notification(u"Suppression de %s" % filename,
                u"Le fichier %s a été supprimé par %s." % (filename, MYUID),
                filename, old)
            os.remove(getpath(filename))
        else:
            return False
    return True

def backup(fname, old):
    """Backupe l'ancienne version du fichier"""
    back = open(getpath(fname, backup=True), 'a')
    back.write(json.dumps(old))
    back.write('\n')
    back.write('* %s: %s\n' % (str(datetime.datetime.now()),corps)) 
    back.close()

def notification(subject, corps, fname, old):
    """Envoie par mail une notification de changement de fichier"""
    conn = smtplib.SMTP('localhost')
    frommail = CRANSP_MAIL
    tomail = DEST_MAIL
    msg = MIMEMultipart(_charset="utf-8")
    msg['Subject'] = subject
    msg['X-Mailer'] = "cranspasswords"
    msg['From'] = CRANSP_MAIL
    msg['To'] = DEST_MAIL
    msg.preamble = "cranspasswords report"
    info = MIMEText(corps + 
        "\nLa version précédente a été sauvegardée." +
        #"\nCi-joint l'ancien fichier." +
        "\n\n-- \nCranspasswords.py",_charset="utf-8")
    msg.attach(info)
    #old = MIMEText(old)
    #old.add_header('Content-Disposition', 'attachment', filename=fname) 
    #msg.attach(str(old))
    conn.sendmail(frommail,tomail,msg.as_string())
    conn.quit()

WRITE_COMMANDS = ["putfile", "rmfile"]

if __name__ == "__main__":
    argv = sys.argv[1:]
    if len(argv) not in [1, 2]:
        sys.exit(1)
    command = argv[0]
    if READONLY and command in WRITE_COMMANDS:
        raise IOError("Ce serveur est read-only.")
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
