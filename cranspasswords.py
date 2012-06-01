#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""cranspasswords: gestion des mots de passe du Cr@ns"""

import sys
import subprocess
import json
import tempfile
import os
import atexit
import argparse

######
## GPG Definitions

GPG = '/usr/bin/gpg'
GPG_ARGS = {
    'decrypt': ['-d'],
    'encrypt': ['--armor', '-es'],
    'fingerprint': ['--fingerprint'],
    'receive-keys': ['--recv-keys'],
    }

DEBUG = False
VERB = False
CLIPBOARD = False # Par défaut, place-t-on le mdp dans le presse-papier ?
FORCED = False #Mode interactif qui demande confirmation
NROLES = None     # Droits à définir sur le fichier en édition

def gpg(command, args = None):
    """Lance gpg pour la commande donnée avec les arguments
    donnés. Renvoie son entrée standard et sa sortie standard."""
    full_command = [GPG]
    full_command.extend(GPG_ARGS[command])
    if args:
        full_command.extend(args)
    if VERB:
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
    if not VERB:
        proc.stderr.close()
    return proc.stdin, proc.stdout

######
## Remote commands

SERVER_CMD_DEBUG = ['/usr/bin/ssh', 'localhost', \
    '/home/dstan/crans/cranspasswords/cranspasswords-server.py']
SERVER_CMD = ['/usr/bin/ssh', 'vo',\
    '/home/dstan/cranspasswords/cranspasswords-server']
USER = 'dstan'

def ssh(command, arg = None):
    """Lance ssh avec les arguments donnés. Renvoie son entrée
    standard et sa sortie standard."""
    full_command = list(SERVER_CMD)
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

def get_my_roles():
    """Retoure la liste des rôles perso"""
    allr = all_roles()
    return filter(lambda role: USER in allr[role],allr.keys())

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
            if VERB:   print "Checking %s" % mail
            if str("<%s>" % mail.lower()) not in stdout.read().lower():
                if VERB:   print "-->Fail on %s" % mail
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
        if VERB: print "Échec de chiffrement"
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
    if NROLES != None:
        roles = NROLES
    if enc_pwd <> None:
        return put_file(name, roles, enc_pwd)
    else:
        return False

def get_password(name):
    """Récupère le mot de passe donné par name"""
    remotefile = get_file(name)
    return decrypt(remotefile['contents'])

## Interface

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
    my_roles = get_my_roles()
    for (fname,froles) in all_files().iteritems():
        access = set(my_roles).intersection(froles) != set([])
        print " %s %s (%s)" % ((access and '+' or '-'),fname,", ".join(froles))
    print """--Mes roles: %s""" % \
        ", ".join(my_roles)

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

def confirm(text):
    if FORCED: return True
    while True:
        out = raw_input(text + ' (O/N)').lower()
        if out == 'o':
            return True
        elif out == 'n':
            return False

def remove_file(fname):
    if not confirm('Êtes-vous sûr de vouloir supprimer %s ?' % fname):
        return
    if rm_file(fname):
        print "Suppression achevée"
    else:
        print "Erreur de suppression (avez-vous les droits ?)"
    

def my_check_keys():
    check_keys() and "Base de clés ok" or "Erreurs dans la base"

def my_update_keys():
    print update_keys()

def update_role(roles=None):
    """ Reencode les fichiers, si roles est fourni,
    contient une liste de rôles"""
    my_roles = get_my_roles()
    if roles == None:
        # On ne conserve que les rôles qui finissent par -w
        roles = [ r[:-2] for r in filter(lambda r: r.endswith('-w'),my_roles)]
    if type(roles) != list:
        roles = [roles]

    for (fname,froles) in all_files().iteritems():
        if set(roles).intersection(froles) == set([]):
            continue
        #if VERB:
        print "Reencodage de %s" % fname
        put_password(fname,froles,get_password(fname))

def parse_roles(strroles):
    if strroles == None: return None
    roles = all_roles()
    my_roles = filter(lambda r: USER in roles[r],roles.keys())
    my_roles_w = [ r[:-2] for r in filter(lambda r: r.endswith('-w'),my_roles) ]
    ret = set()
    writable = False
    for role in strroles.split(','):
        if role not in roles.keys():
            print("Le rôle %s n'existe pas !" % role)
            return False
        if role.endswith('-w'):
            print("Le rôle %s ne devrait pas être utilisé ! (utilisez %s)"
                % (role,role[:-2]))
            return False
        writable = writable or role in my_roles_w
        ret.add(role)
    
    if not FORCED and not writable:
        if not confirm("Vous vous apprêtez à perdre vos droits d'écritures (role ne contient pas %s) sur ce fichier, continuer ?" % ", ".join(my_roles_w)):
            return False
    return list(ret)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="trousseau crans")
    parser.add_argument('--test',action='store_true',default=False,
        help='Utilisation du serveur de test')
    parser.add_argument('-v','--verbose',action='store_true',default=False,
        help="Mode verbeux")
    parser.add_argument('-c','--clipboard',action='store_true',default=False,
        help="Stocker le mot de passe dans le presse papier")
    parser.add_argument('-f','--force',action='store_true',default=False,
        help="Forcer l'action")

    # Actions possibles
    action_grp = parser.add_mutually_exclusive_group(required=False)
    action_grp.add_argument('--edit',action='store_const',dest='action',
        default=show_file,const=edit_file,
        help="Editer")
    action_grp.add_argument('--view',action='store_const',dest='action',
        default=show_file,const=show_file,
        help="Voir")
    action_grp.add_argument('--remove',action='store_const',dest='action',
        default=show_file,const=remove_file,
        help="Effacer")
    action_grp.add_argument('-l','--list',action='store_const',dest='action',
        default=show_file,const=show_files,
        help="Lister les fichiers")
    action_grp.add_argument('--check-keys',action='store_const',dest='action',
        default=show_file,const=my_check_keys,
        help="Vérifier les clés")
    action_grp.add_argument('--update-keys',action='store_const',dest='action',
        default=show_file,const=my_update_keys,
        help="Mettre à jour les clés")
    action_grp.add_argument('--list-roles',action='store_const',dest='action',
        default=show_file,const=show_roles,
        help="Lister les rôles des gens")
    action_grp.add_argument('--recrypt-role',action='store_const',dest='action',
        default=show_file,const=update_role,
        help="Met à jour (reencode les roles)")

    parser.add_argument('--roles',nargs='?',default=None,
        help="liste des roles à affecter au fichier")
    parser.add_argument('fname',nargs='?',default=None,
        help="Nom du fichier à afficher")

    parsed = parser.parse_args(sys.argv[1:])
    DEBUG = parsed.test
    if DEBUG:
       SERVER_CMD = SERVER_CMD_DEBUG 
    VERB = parsed.verbose
    CLIPBOARD = parsed.clipboard
    FORCED = parsed.force
    NROLES = parse_roles(parsed.roles)

    if NROLES != False:
        if parsed.action.func_code.co_argcount == 0:
            parsed.action()
        elif parsed.fname == None:
            print("Vous devez fournir un nom de fichier avec cette commande")
            parser.print_help()
        else:
            parsed.action(parsed.fname)

