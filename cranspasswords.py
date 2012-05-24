#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""cranspasswords: gestion des mots de passe du Cr@ns"""

import sys
import subprocess
import json
import tempfile
import os
import atexit

######
## GPG Definitions

GPG = '/usr/bin/gpg'
GPG_ARGS = {
    'decrypt': ['-d'],
    'encrypt': ['--armor', '-es'],
    'fingerprint': ['--fingerprint'],
    'receive-keys': ['--recv-keys'],
    }

DEBUG=False
CLIPBOARD=False # Par défaut, place-t-on le mdp dans le presse-papier ?

def gpg(command, args = None):
    """Lance gpg pour la commande donnée avec les arguments
    donnés. Renvoie son entrée standard et sa sortie standard."""
    full_command = [GPG]
    full_command.extend(GPG_ARGS[command])
    if args:
        full_command.extend(args)
    if DEBUG:
        stderr=sys.stderr
    else:
        stderr=subprocess.PIPE
        full_command.extend(['--debug-level=1'])
    #print full_command
    proc = subprocess.Popen(full_command,
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = stderr,
                            close_fds = True)
    if not DEBUG:
        proc.stderr.close()
    return proc.stdin, proc.stdout

######
## Remote commands

SSH = '/usr/bin/ssh'
SSH_HOST = 'localhost'
REMOTE_COMMAND = ['/home/dstan/crans/cranspasswords/cranspasswords-server.py']

def ssh(command, arg = None):
    """Lance ssh avec les arguments donnés. Renvoie son entrée
    standard et sa sortie standard."""
    full_command = [SSH, SSH_HOST]
    full_command.extend(REMOTE_COMMAND)
    full_command.append(command)
    if arg:
        full_command.append(arg)
    proc = subprocess.Popen(full_command,
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = sys.stderr,
                            close_fds = True)
    return proc.stdin, proc.stdout

def remote_command(command, arg = None, stdin_contents = None):
    """Exécute la commande distante, et retourne la sortie de cette
    commande"""
    
    sshin, sshout = ssh(command, arg)
    if stdin_contents:
        sshin.write(json.dumps(stdin_contents))
        sshin.close()
    return json.loads(sshout.read())

def all_keys():
    """Récupère les clés du serveur distant"""
    return remote_command("listkeys")

def all_roles():
    """Récupère les roles du serveur distant"""
    return remote_command("listroles")

def all_files():
    """Récupère les fichiers du serveur distant"""
    return remote_command("listfiles")

def get_file(filename):
    """Récupère le contenu du fichier distant"""
    return remote_command("getfile", filename)

def put_file(filename, roles, contents):
    """Dépose le fichier sur le serveur distant"""
    return remote_command("putfile", filename, {'roles': roles,
                                                'contents': contents})
def rm_file(filename):
    """Supprime le fichier sur le serveur distant"""
    return remote_command("rmfile", filename)

######
## Local commands

def update_keys():
    """Met à jour les clés existantes"""

    keys = all_keys()

    _, stdout = gpg("receive-keys", [key for _, key in keys.values() if key])
    return stdout.read()

def check_keys():
    """Vérifie les clés existantes"""

    keys = all_keys()

    for mail, key in keys.values():
        if key:
            _, stdout = gpg("fingerprint", [key])
            if DEBUG:   print "Checking %s" % mail
            if str("<%s>" % mail.lower()) not in stdout.read().lower():
                if DEBUG:   print "-->Fail on %s" % mail
                break
    else:
        return True

    return False

def encrypt(roles, contents):
    """Chiffre le contenu pour les roles donnés"""

    recipients = set()
    allroles = all_roles()
    allkeys = all_keys()
    
    email_recipients = []
    for role in roles:
        for recipient in allroles[role]:
            recipients.add(recipient)
    for recipient in recipients:
        email, key = allkeys[recipient]
        if key:
            email_recipients.append("-r")
            email_recipients.append(email)

    stdin, stdout = gpg("encrypt", email_recipients)
    stdin.write(contents)
    stdin.close()
    out = stdout.read()
    if out == '':
        if DEBUG: print "Échec de chiffrement"
        return None
    else:
        return out

def decrypt(contents):
    """Déchiffre le contenu"""
    stdin, stdout = gpg("decrypt")
    stdin.write(contents)
    stdin.close()
    return stdout.read()

def put_password(name, roles, contents):
    """Dépose le mot de passe après l'avoir chiffré pour les
    destinataires donnés"""
    enc_pwd = encrypt(roles, contents)
    if enc_pwd <> None:
        return put_file(name, roles, enc_pwd)
    else:
        return False

def get_password(name):
    """Récupère le mot de passe donné par name"""
    remotefile = get_file(name)
    return decrypt(remotefile['contents'])

## Interface
def usage():
    print """Cranspasswords 2 Usage:
 cranspasswords [options] [<filename>]
 cranspasswords <filename>      Télécharge le fichier
 cranspasswords                 Mode interactif

Options:
 --view                     Télécharge le fichier
# --upload                   Upload un nouveau fichier depuis stdin
 --edit                     Lance $EDITOR sur le fichier
# --roles=<role1>,<role2>…   Définit les rôles
# --roles+=<role>            Ajoute un rôle
# --roles-=<role>            Supprime un rôle
# --edit-roles               Lance $EDITOR sur les rôles
# --rm                       Supprime le fichier
 --update-keys              Mets à jour les clés
 --check-keys               Vérifie les clés
 -l, --list                 Liste les fichiers disponibles
 --list-roles               Liste des rôles disponibles
 -c, --clipboard            mot de passe en presse papier"""

def editor(texte):
    """ Lance $EDITOR sur texte"""
    f = tempfile.NamedTemporaryFile()
    atexit.register(f.close)
    f.write(texte)
    f.flush()
    proc = subprocess.Popen(os.getenv('EDITOR') + ' ' + f.name,shell=True)
    os.waitpid(proc.pid,0)
    f.seek(0)
    ntexte = f.read()
    f.close()
    return texte <> ntexte and ntexte or None

def show_files():
    print """Liste des fichiers disponibles""" 
    for fname in all_files():
        print " * " + fname

def show_roles():
    print """Liste des roles disponibles""" 
    for role in all_roles().keys():
        if role.endswith('-w'): continue
        print " * " + role 

def clipboard(texte):
    proc =subprocess.Popen(['xclip','-selection','clipboard'],\
        stdin=subprocess.PIPE,stdout=sys.stdout,stderr=sys.stderr)
    proc.stdin.write(texte)
    proc.stdin.close()
    print "[Le mot de passe a été mis dans le presse papier]"


def show_file(fname):
    value = get_file(fname)
    if value == False:
        print "Fichier introuvable"; return
    print "Fichier %s:" % fname
    (sin,sout) = gpg('decrypt')
    sin.write(value['contents'])
    sin.close()
    texte = sout.read()
    if CLIPBOARD:    # Ça ne va pas plaire à tout le monde
        lines = texte.split('\n')
        if len(lines) == 2:
            clipboard(lines[0])
        else:
            for line in lines:
                if line.startswith('pass:'):
                    clipboard(line[5:].strip(' \t\r\n'))
                else:
                    print line
    else:
        print texte
    print "-----"
    print "Visible par: %s" % ','.join(value['roles'])
    # Todo: some clipboard facility
        
def edit_file(fname):
    value = get_file(fname)
    if value == False:
        print "Fichier introuvable"; return
    (sin,sout) = gpg('decrypt')
    sin.write(value['contents'])
    sin.close()
    texte = sout.read()
    ntexte = editor(texte)
    if ntexte == None:
        print "Pas de modifications effectuées"
    else:
        if put_password(fname,value['roles'],ntexte):
            print "Modifications enregistrées"
        else:
            print "Erreur lors de l'enregistrement (avez-vous les droits suffisants ?)"
        

if __name__ == "__main__":
    argv = sys.argv[1:]
    if '-c' in argv or '--clipboard' in argv:
        CLIPBOARD=True
    action = show_file
    if '--edit' in argv:
        action = edit_file
    if '-v' in argv:    #Verbose !
        DEBUG = True
    for arg in argv:
        if arg in ['--list','-l']:
            show_files()
        elif not arg.startswith('-'):
            action(arg)
        elif arg == '--check-keys':
            print check_keys() and "Base de clés ok" or "Erreurs dans la base"
        elif arg == '--update-keys':
            print update_keys()
        elif arg == '--list-roles':
            show_roles()
        elif arg in ['-c','--clipboard','--view','--edit','-v']:
            pass
        else:
            usage()
            break

