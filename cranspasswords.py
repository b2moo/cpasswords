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
import re
import random
import string
import datetime
try:
    import clientconfig as config
except ImportError:
    print "Read the README"
    sys.exit(1)

## Password pattern in files:
PASS = re.compile('[\t ]*pass(?:word)?[\t ]*:[\t ]*(.*)\r?\n?$', \
        flags=re.IGNORECASE)

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
# Par défaut, place-t-on le mdp dans le presse-papier ?
CLIPBOARD = bool(os.getenv('DISPLAY')) and os.path.exists('/usr/bin/xclip')
FORCED = False #Mode interactif qui demande confirmation
NROLES = None     # Droits à définir sur le fichier en édition
SERVER = None

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


class simple_memoize(object):
    """ Memoization/Lazy """
    def __init__(self, f):
        self.f = f
        self.val = None

    def __call__(self):
        if self.val==None:
            self.val = self.f()
        return self.val

######
## Remote commands


def ssh(command, arg = None):
    """Lance ssh avec les arguments donnés. Renvoie son entrée
    standard et sa sortie standard."""
    full_command = list(SERVER['server_cmd'])
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

@simple_memoize
def all_keys():
    """Récupère les clés du serveur distant"""
    return remote_command("listkeys")

@simple_memoize
def all_roles():
    """Récupère les roles du serveur distant"""
    return remote_command("listroles")

@simple_memoize
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

@simple_memoize
def get_my_roles():
    """Retoure la liste des rôles perso"""
    allr = all_roles()
    return filter(lambda role: SERVER['user'] in allr[role],allr.keys())

def gen_password():
    """Generate random password"""
    random.seed(datetime.datetime.now().microsecond)
    chars = string.letters + string.digits + '/=+*'
    length = 15
    return ''.join([random.choice(chars) for _ in xrange(length)])

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

def get_recipients_of_roles(roles):
    """Renvoie les destinataires d'un rôle"""
    recipients = set()
    allroles = all_roles()
    for role in roles:
        for recipient in allroles[role]:
            recipients.add(recipient)

    return recipients

def get_dest_of_roles(roles):
    """ Summarize recipients of a role """
    allkeys = all_keys()
    return ["%s (%s)" % (rec, allkeys[rec]) for rec in \
        get_recipients_of_roles(roles) if allkeys[rec]]

def encrypt(roles, contents):
    """Chiffre le contenu pour les roles donnés"""

    allkeys = all_keys()
    recipients = get_recipients_of_roles(roles)
    
    email_recipients = []
    for recipient in recipients:
        key = allkeys[recipient]
        if key:
            email_recipients.append("-r")
            email_recipients.append(key)

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
        if VERB:
            print "Pas de nouveaux rôles"
    if enc_pwd <> None:
        return put_file(name, roles, enc_pwd)
    else:
        return False

def get_password(name):
    """Récupère le mot de passe donné par name"""
    remotefile = get_file(name)
    return decrypt(remotefile['contents'])

## Interface

def editor(texte, annotations=""):
    """ Lance $EDITOR sur texte.
    Renvoie le nouveau texte si des modifications ont été apportées, ou None
    """

    # Avoid syntax hilight with ".txt". Would be nice to have some colorscheme
    # for annotations ...
    f = tempfile.NamedTemporaryFile(suffix='.txt')
    atexit.register(f.close)
    f.write(texte)
    for l in annotations.split('\n'):
        f.write("# %s\n" % l.encode('utf-8'))
    f.flush()
    proc = subprocess.Popen(os.getenv('EDITOR') + ' ' + f.name,shell=True)
    os.waitpid(proc.pid,0)
    f.seek(0)
    ntexte = f.read()
    f.close()
    ntexte = '\n'.join(filter(lambda l: not l.startswith('#'), ntexte.split('\n')))
    if texte != ntexte:
        return ntexte
    return None

def show_files():
    proc = subprocess.Popen("cat",stdin=subprocess.PIPE,shell=True)
    out = proc.stdin
    out.write("""Liste des fichiers disponibles\n""" )
    my_roles = get_my_roles()
    files = all_files()
    keys = files.keys()
    keys.sort()
    for fname in keys:
        froles = files[fname]
        access = set(my_roles).intersection(froles) != set([])
        out.write(" %s %s (%s)\n" % ((access and '+' or '-'),fname,", ".join(froles)))
    out.write("""--Mes roles: %s\n""" % \
        ", ".join(my_roles))
    
    out.close()
    os.waitpid(proc.pid,0)

def show_roles():
    print """Liste des roles disponibles"""
    for role in all_roles().keys():
        if role.endswith('-w'): continue
        print " * " + role 

def show_servers():
    print """Liste des serveurs disponibles"""
    for server in config.servers.keys():
        print " * " + server

old_clipboard = None
def saveclipboard(restore=False):
    global old_clipboard
    if restore and old_clipboard == None:
        return
    act = '-in' if restore else '-out'
    proc =subprocess.Popen(['xclip',act,'-selection','clipboard'],\
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=sys.stderr)
    if not restore:
        old_clipboard = proc.stdout.read()
    else:
        raw_input("Appuyez sur Entrée pour récupérer le contenu précédent du presse papier.")
        proc.stdin.write(old_clipboard)
    proc.stdin.close()
    proc.stdout.close()

def clipboard(texte):
    saveclipboard()
    proc =subprocess.Popen(['xclip','-selection','clipboard'],\
        stdin=subprocess.PIPE,stdout=sys.stdout,stderr=sys.stderr)
    proc.stdin.write(texte)
    proc.stdin.close()
    return "[Le mot de passe a été mis dans le presse papier]"


def show_file(fname):
    value = get_file(fname)
    if value == False:
        print "Fichier introuvable"
        return
    (sin,sout) = gpg('decrypt')
    sin.write(value['contents'])
    sin.close()
    texte = sout.read()
    ntexte = ""
    hidden = False  # Est-ce que le mot de passe a été caché ?
    lines = texte.split('\n')
    for line in lines:
        catchPass = PASS.match(line)
        if catchPass != None and CLIPBOARD:
            hidden=True
            line = clipboard(catchPass.group(1))
        ntexte += line + '\n'
    showbin = "cat" if hidden else "less"
    proc = subprocess.Popen(showbin, stdin=subprocess.PIPE, shell=True)
    out = proc.stdin
    out.write("Fichier %s:\n\n" % fname)
    out.write(ntexte)
    out.write("-----\n")
    out.write("Visible par: %s\n" % ','.join(value['roles']))
    out.close()
    os.waitpid(proc.pid, 0)

        
def edit_file(fname):
    value = get_file(fname)
    nfile = False
    annotations = u""
    if value == False:
        nfile = True
        print "Fichier introuvable"
        if not confirm("Créer fichier ?"):
            return
        annotations += u"""Ceci est un fichier initial contenant un mot de passe
aléatoire, pensez à rajouter une ligne "login: ${login}" """
        texte = "pass: %s\n" % gen_password()
        roles = get_my_roles()
        # Par défaut les roles d'un fichier sont ceux en écriture de son
        # créateur
        roles = [ r[:-2] for r in roles if r.endswith('-w') ]
        if roles == []:
            print "Vous ne possédez aucun rôle en écriture ! Abandon."
            return
        value = {'roles':roles}
    else:
        (sin,sout) = gpg('decrypt')
        sin.write(value['contents'])
        sin.close()
        texte = sout.read()
    value['roles'] = NROLES or value['roles']

    annotations += u"Ce fichier sera chiffré pour les rôles suivants :\n%s\n\
C'est-à-dire pour les utilisateurs suivants :\n%s" % (
           ', '.join(value['roles']),
           '\n'.join(' %s' % rec for rec in get_dest_of_roles(value['roles']))
        )
        
    ntexte = editor(texte, annotations)

    if ntexte == None and not nfile and NROLES == None:
        print "Pas de modifications effectuées"
    else:
        ntexte = texte if ntexte == None else ntexte
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

def update_role():
    roles = None
    """ Reencode les fichiers, si roles est fourni,
    contient une liste de rôles"""
    my_roles = get_my_roles()
    if roles == None:
        # On ne conserve que les rôles qui finissent par -w
        roles = [ r[:-2] for r in my_roles if r.endswith('-w')]
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
    my_roles = filter(lambda r: SERVER['user'] in roles[r],roles.keys())
    my_roles_w = [ r[:-2] for r in my_roles if r.endswith('-w') ]
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
        if not confirm("""Vous vous apprêtez à perdre vos droits d'écritures\
(role ne contient pas %s) sur ce fichier, continuer ?""" % \
            ", ".join(my_roles_w)):
            return False
    return list(ret)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="trousseau crans")
    parser.add_argument('--server',default='default',
        help='Utilisation d\'un serveur alternatif (test, etc)')
    parser.add_argument('-v','--verbose',action='store_true',default=False,
        help="Mode verbeux")
    parser.add_argument('-c','--clipboard',action='store_true',default=None,
        help="Stocker le mot de passe dans le presse papier")
    parser.add_argument('--no-clip', '--noclip', '--noclipboard',action='store_false',default=None,
        dest='clipboard',
        help="Ne PAS stocker le mot de passe dans le presse papier")
    parser.add_argument('-f','--force',action='store_true',default=False,
        help="Forcer l'action")

    # Actions possibles
    action_grp = parser.add_mutually_exclusive_group(required=False)
    action_grp.add_argument('-e', '--edit',action='store_const',dest='action',
        default=show_file,const=edit_file,
        help="Editer (ou créer)")
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
    action_grp.add_argument('--list-servers',action='store_const',dest='action',
        default=show_file,const=show_servers,
        help="Lister les rôles serveurs")
    action_grp.add_argument('--recrypt-role',action='store_const',dest='action',
        default=show_file,const=update_role,
        help="Met à jour (reencode les roles)")

    parser.add_argument('--roles',nargs='?',default=None,
        help="liste des roles à affecter au fichier")
    parser.add_argument('fname',nargs='?',default=None,
        help="Nom du fichier à afficher")

    parsed = parser.parse_args(sys.argv[1:])
    SERVER = config.servers[parsed.server]
    VERB = parsed.verbose
    DEBUG = VERB
    if parsed.clipboard != None:
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
    
    saveclipboard(restore=True)

