#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""Gestion centralisée des mots de passe avec chiffrement GPG

Copyright (C) 2010-2013 Cr@ns <roots@crans.org>
Authors : Daniel Stan <daniel.stan@crans.org>
          Vincent Le Gallic <legallic@crans.org>
"""

from __future__ import print_function

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
import gnupg
try:
    import gnupg #disponible seulement sous wheezy
except ImportError:
    if sys.stderr.isatty() and not any([opt in sys.argv for opt in ["-q", "--quiet"]]):
        sys.stderr.write(u"Package python-gnupg introuvable, vous ne pourrez pas vérifiez les clés.\n".encode("utf-8"))
try:
    # Oui, le nom de la commande est dans la config, mais on n'a pas encore accès à la config
    bootstrap_cmd_name = os.path.split(sys.argv[0])[1]
    sys.path.append(os.path.expanduser("~/.config/%s/" % (bootstrap_cmd_name,)))
    import clientconfig as config
except ImportError:
    if sys.stderr.isatty() and not any([opt in sys.argv for opt in ["-q", "--quiet"]]):
        sys.stderr.write(u"Va lire le fichier README.\n".encode("utf-8"))
    sys.exit(1)

#: pattern utilisé pour détecter la ligne contenant le mot de passe dans les fichiers
PASS = re.compile('[\t ]*pass(?:word)?[\t ]*:[\t ]*(.*)\r?\n?$',
        flags=re.IGNORECASE)

## GPG Definitions
#: path gu binaire gpg
GPG = '/usr/bin/gpg'
#: paramètres à fournir à gpg en fonction de l'action désirée
GPG_ARGS = {
    'decrypt' : ['-d'],
    'encrypt' : ['--armor', '-es'],
    'fingerprint' : ['--fingerprint'],
    'receive-keys' : ['--recv-keys'],
    }
#: map lettre de trustlevel -> (signification, faut-il faire confiance à la clé)
GPG_TRUSTLEVELS = {
                    u"-" : (u"inconnue", False),
                    u"n" : (u"nulle", False),
                    u"m" : (u"marginale", True),
                    u"f" : (u"entière", True),
                    u"u" : (u"ultime", True),
                    u"r" : (u"révoquée", False),
                    u"e" : (u"expirée", False),
                    u"q" : (u"/données insuffisantes/", False),
                  }
#: Mode verbeux
VERB = False
#: Par défaut, place-t-on le mdp dans le presse-papier ?
CLIPBOARD = bool(os.getenv('DISPLAY')) and os.path.exists('/usr/bin/xclip')
#: Mode «ne pas demander confirmation»
FORCED = False
#: Droits à définir sur le fichier en édition
NEWROLES = None
#: Serveur à interroger (peuplée à l'exécution)
SERVER = None

def gpg(command, args = None):
    """Lance gpg pour la commande donnée avec les arguments
    donnés. Renvoie son entrée standard et sa sortie standard."""
    full_command = [GPG]
    full_command.extend(GPG_ARGS[command])
    if args:
        full_command.extend(args)
    if VERB:
        stderr = sys.stderr
    else:
        stderr = subprocess.PIPE
        full_command.extend(['--debug-level=1'])
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
        if self.val == None:
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
    if not stdin_contents is None:
        sshin.write(json.dumps(stdin_contents))
        sshin.close()
    raw_out = sshout.read()
    return json.loads(raw_out)

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

def get_files(filenames):
    """Récupère le contenu des fichiers distants"""
    return remote_command("getfiles", stdin_contents=filenames)

def put_files(files):
    """Dépose les fichiers sur le serveur distant"""
    return remote_command("putfiles", stdin_contents=files)

def rm_file(filename):
    """Supprime le fichier sur le serveur distant"""
    return remote_command("rmfile", filename)

@simple_memoize
def get_my_roles():
    """Retourne la liste des rôles de l'utilisateur"""
    allr = all_roles()
    return filter(lambda role: SERVER['user'] in allr[role], allr.keys())

def gen_password():
    """Génère un mot de passe aléatoire"""
    random.seed(datetime.datetime.now().microsecond)
    chars = string.letters + string.digits + '/=+*'
    length = 15
    return u''.join([random.choice(chars) for _ in xrange(length)])

######
## Local commands

def update_keys():
    """Met à jour les clés existantes"""
    
    keys = all_keys()
    
    _, stdout = gpg("receive-keys", [key for _, key in keys.values() if key])
    return stdout.read().decode("utf-8")

def check_keys():
    """Vérifie les clés existantes"""
    if VERB:
        print("M : l'uid correspond au mail du fingerprint\nC : confiance OK (inclu la vérification de non expiration).\n")
    keys = all_keys()
    gpg = gnupg.GPG()
    localkeys = gpg.list_keys()
    failed = False
    for (mail, fpr) in keys.values():
        if fpr:
            if VERB:
                print((u"Checking %s… " % (mail)).encode("utf-8"), end="")
            corresponds = [key for key in localkeys if key["fingerprint"] == fpr]
            # On vérifie qu'on possède la clé…
            if len(corresponds) == 1:
                correspond = corresponds[0]
                # …qu'elle correspond au mail…
                if mail.lower() in sum([re.findall("<(.*)>", uid.lower()) for uid in correspond["uids"]], []):
                    if VERB:
                        print("M ", end="")
                    meaning, trustvalue = GPG_TRUSTLEVELS[correspond["trust"]]
                    # … et qu'on lui fait confiance
                    if not trustvalue:
                        print((u"--> Fail on %s:%s\nLa confiance en la clé est : %s" % (fpr, mail, meaning,)).encode("utf-8"))
                        failed = True
                    elif VERB:
                        print("C ", end="")
                else:
                    print((u"--> Fail on %s:%s\n!! Le fingerprint et le mail ne correspondent pas !" % (fpr, mail)).encode("utf-8"))
                    failed = True
            else:
                print((u"--> Fail on %s:%s\nPas (ou trop) de clé avec ce fingerprint." % (fpr, mail)).encode("utf-8"))
                failed = True
            if VERB:
                print("")
    return not failed

def get_recipients_of_roles(roles):
    """Renvoie les destinataires d'un rôle"""
    recipients = set()
    allroles = all_roles()
    for role in roles:
        for recipient in allroles[role]:
            recipients.add(recipient)
    return recipients

def get_dest_of_roles(roles):
    """Renvoie la liste des "username : mail (fingerprint)" """
    allkeys = all_keys()
    return [u"%s : %s (%s)" % (rec, allkeys[rec][0], allkeys[rec][1])
               for rec in get_recipients_of_roles(roles) if allkeys[rec][1]]

def encrypt(roles, contents):
    """Chiffre ``contents`` pour les ``roles`` donnés"""
    allkeys = all_keys()
    recipients = get_recipients_of_roles(roles)
    
    fpr_recipients = []
    for recipient in recipients:
        fpr = allkeys[recipient][1]
        if fpr:
            fpr_recipients.append("-r")
            fpr_recipients.append(fpr)
    
    stdin, stdout = gpg("encrypt", fpr_recipients)
    stdin.write(contents.encode("utf-8"))
    stdin.close()
    out = stdout.read().decode("utf-8")
    if out == '':
        return [False, u"Échec de chiffrement"]
    else:
        return [True, out]

def decrypt(contents):
    """Déchiffre le contenu"""
    stdin, stdout = gpg("decrypt")
    stdin.write(contents.encode("utf-8"))
    stdin.close()
    return stdout.read().decode("utf-8")

def put_password(name, roles, contents):
    """Dépose le mot de passe après l'avoir chiffré pour les
    destinataires donnés"""
    success, enc_pwd_or_error = encrypt(roles, contents)
    if NEWROLES != None:
        roles = NEWROLES
        if VERB:
            print(u"Pas de nouveaux rôles".encode("utf-8"))
    if success:
        enc_pwd = enc_pwd_or_error
        return put_files([{'filename' : name, 'roles' : roles, 'contents' : enc_pwd}])[0]
    else:
        error = enc_pwd_or_error
        return [False, error]

def get_password(name):
    """Récupère le mot de passe donné par name"""
    gotit, remotefile = get_files([name])[0]
    if gotit:
        remotefile = decrypt(remotefile['contents'])
    return [gotit, remotefile]

######
## Interface

def editor(texte, annotations=u""):
    """ Lance $EDITOR sur texte.
    Renvoie le nouveau texte si des modifications ont été apportées, ou None
    """
    
    # Avoid syntax hilight with ".txt". Would be nice to have some colorscheme
    # for annotations ...
    f = tempfile.NamedTemporaryFile(suffix='.txt')
    atexit.register(f.close)
    if annotations:
        annotations = "# " + annotations.replace("\n", "\n# ")
    f.write((texte + "\n" + annotations).encode("utf-8"))
    f.flush()
    proc = subprocess.Popen([os.getenv('EDITOR', '/usr/bin/editor'), f.name])
    os.waitpid(proc.pid, 0)
    f.seek(0)
    ntexte = f.read().decode("utf-8")
    f.close()
    ntexte = u'\n'.join(filter(lambda l: not l.startswith('#'), ntexte.split('\n')))
    return ntexte

def show_files():
    """Affiche la liste des fichiers disponibles sur le serveur distant"""
    print(u"Liste des fichiers disponibles :".encode("utf-8"))
    my_roles = get_my_roles()
    files = all_files()
    keys = files.keys()
    keys.sort()
    for fname in keys:
        froles = files[fname]
        access = set(my_roles).intersection(froles) != set([])
        print((u" %s %s (%s)" % ((access and '+' or '-'), fname, ", ".join(froles))).encode("utf-8"))
    print((u"""--Mes roles: %s""" % (", ".join(my_roles),)).encode("utf-8"))
    
def show_roles():
    """Affiche la liste des roles existants"""
    print(u"Liste des roles disponibles".encode("utf-8"))
    for (role, usernames) in all_roles().iteritems():
        if not role.endswith('-w'):
            print((u" * %s : %s" % (role, ", ".join(usernames))).encode("utf-8"))

def show_servers():
    """Affiche la liste des serveurs disponibles"""
    print(u"Liste des serveurs disponibles".encode("utf-8"))
    for server in config.servers.keys():
        print((u" * " + server).encode("utf-8"))

old_clipboard = None
def saveclipboard(restore=False):
    """Enregistre le contenu du presse-papier. Le rétablit si ``restore=True``"""
    global old_clipboard
    if restore and old_clipboard == None:
        return
    act = '-in' if restore else '-out'
    proc = subprocess.Popen(['xclip', act, '-selection', 'clipboard'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
    if not restore:
        old_clipboard = proc.stdout.read()
    else:
        raw_input(u"Appuyez sur Entrée pour récupérer le contenu précédent du presse papier.".encode("utf-8"))
        proc.stdin.write(old_clipboard)
    proc.stdin.close()
    proc.stdout.close()

def clipboard(texte):
    """Place ``texte`` dans le presse-papier en mémorisant l'ancien contenu."""
    saveclipboard()
    proc =subprocess.Popen(['xclip', '-selection', 'clipboard'],\
        stdin=subprocess.PIPE, stdout=sys.stdout, stderr=sys.stderr)
    proc.stdin.write(texte.encode("utf-8"))
    proc.stdin.close()
    return u"[Le mot de passe a été mis dans le presse papier]"


def show_file(fname):
    """Affiche le contenu d'un fichier"""
    gotit, value = get_files([fname])[0]
    if not gotit:
        print(value.encode("utf-8")) # value contient le message d'erreur
        return
    (sin, sout) = gpg('decrypt')
    sin.write(value['contents'].encode("utf-8"))
    sin.close()
    texte = sout.read().decode("utf-8")
    ntexte = u""
    hidden = False  # Est-ce que le mot de passe a été caché ?
    lines = texte.split('\n')
    for line in lines:
        catchPass = PASS.match(line)
        if catchPass != None and CLIPBOARD:
            hidden = True
            line = clipboard(catchPass.group(1))
        ntexte += line + '\n'
    showbin = "cat" if hidden else "less"
    proc = subprocess.Popen([showbin], stdin=subprocess.PIPE)
    out = proc.stdin
    raw = u"Fichier %s:\n\n%s-----\nVisible par: %s\n" % (fname, ntexte, ','.join(value['roles']))
    out.write(raw.encode("utf-8"))
    out.close()
    os.waitpid(proc.pid, 0)

        
def edit_file(fname):
    """Modifie/Crée un fichier"""
    gotit, value = get_files([fname])[0]
    nfile = False
    annotations = u""
    if not gotit and not "pas les droits" in value:
        nfile = True
        print(u"Fichier introuvable".encode("utf-8"))
        if not confirm(u"Créer fichier ?"):
            return
        annotations += u"""Ceci est un fichier initial contenant un mot de passe
aléatoire, pensez à rajouter une ligne "login: ${login}"
Enregistrez le fichier vide pour annuler.\n"""
        texte = u"pass: %s\n" % gen_password()
        roles = get_my_roles()
        # Par défaut les roles d'un fichier sont ceux en écriture de son
        # créateur
        roles = [ r[:-2] for r in roles if r.endswith('-w') ]
        if roles == []:
            print(u"Vous ne possédez aucun rôle en écriture ! Abandon.".encode("utf-8"))
            return
        value = {'roles' : roles}
    elif not gotit:
        print(value.encode("utf-8")) # value contient le message d'erreur
        return
    else:
        (sin, sout) = gpg('decrypt')
        sin.write(value['contents'].encode("utf-8"))
        sin.close()
        texte = sout.read().decode("utf-8")
    # On récupère les nouveaux roles si ils ont été précisés, sinon on garde les mêmes
    value['roles'] = NEWROLES or value['roles']
    
    annotations += u"""Ce fichier sera chiffré pour les rôles suivants :\n%s\n
C'est-à-dire pour les utilisateurs suivants :\n%s""" % (
           ', '.join(value['roles']),
           '\n'.join(' %s' % rec for rec in get_dest_of_roles(value['roles']))
        )
        
    ntexte = editor(texte, annotations)
    
    if ((not nfile and ntexte in [u'', texte] and NEWROLES == None) or # Fichier existant vidé ou inchangé
        (nfile and ntexte == u'')):                                  # Nouveau fichier créé vide
        print(u"Pas de modification effectuée".encode("utf-8"))
    else:
        ntexte = texte if ntexte == None else ntexte
        success, message = put_password(fname, value['roles'], ntexte)
        print(message.encode("utf-8"))

def confirm(text):
    """Demande confirmation, sauf si on est mode ``FORCED``"""
    if FORCED: return True
    while True:
        out = raw_input((text + u' (O/N)').encode("utf-8")).lower()
        if out == 'o':
            return True
        elif out == 'n':
            return False

def remove_file(fname):
    """Supprime un fichier"""
    if not confirm(u'Êtes-vous sûr de vouloir supprimer %s ?' % fname):
        return
    message = rm_file(fname)
    print(message.encode("utf-8"))


def my_check_keys():
    """Vérifie les clés et affiche un message en fonction du résultat"""
    print(u"Vérification que les clés sont valides (uid correspondant au login) et de confiance.")
    print((check_keys() and u"Base de clés ok" or u"Erreurs dans la base").encode("utf-8"))

def my_update_keys():
    """Met à jour les clés existantes et affiche le résultat"""
    print(update_keys().encode("utf-8"))

def recrypt_files():
    """Rechiffre les fichiers"""
    # Ici, la signification de NEWROLES est : on ne veut rechiffrer que les fichiers qui ont au moins un de ces roles
    rechiffre_roles = NEWROLES
    my_roles = get_my_roles()
    my_roles_w = [r for r in my_roles if r.endswith("-w")]
    if rechiffre_roles == None:
        # Sans précisions, on prend tous les roles qu'on peut
        rechiffre_roles = my_roles
    # On ne conserve que les rôles en écriture
    rechiffre_roles = [ r[:-2] for r in rechiffre_roles if r.endswith('-w')]
    
    # La liste des fichiers
    allfiles = all_files()
    # On ne demande que les fichiers dans lesquels on peut écrire
    # et qui ont au moins un role dans ``roles``
    askfiles = [filename for (filename, fileroles) in allfiles.iteritems()
                         if set(fileroles).intersection(roles) != set()
                         and set(fileroles).intersection(my_roles_w) != set()]
    files = get_files(askfiles)
    # Au cas où on aurait échoué à récupérer ne serait-ce qu'un de ces fichiers,
    # on affiche le message d'erreur correspondant et on abandonne.
    for (success, message) in files:
        if not success:
            print(message.encode("utf-8"))
            return
    # On rechiffre
    to_put = [{'filename' : f['filename'],
               'roles' : f['roles'],
               'contents' : encrypt(f['roles'], decrypt(f['contents']))}
              for f in files]
    if to_put:
        print((u"Rechiffrement de %s" % (", ".join([f['filename'] for f in to_put]))).encode("utf-8"))
        results = put_files(to_put)
        # On affiche les messages de retour
        for i in range(len(results)):
            print (u"%s : %s" % (to_put[i]['filename'], results[i][1]))
    else:
        print(u"Aucun fichier n'a besoin d'être rechiffré".encode("utf-8"))

def parse_roles(strroles):
    """Interprête une liste de rôles fournie par l'utilisateur.
       Renvoie ``False`` si au moins un de ces rôles pose problème."""
    if strroles == None: return None
    roles = all_roles()
    my_roles = filter(lambda r: SERVER['user'] in roles[r], roles.keys())
    my_roles_w = [ r[:-2] for r in my_roles if r.endswith('-w') ]
    ret = set()
    writable = False
    for role in strroles.split(','):
        if role not in roles.keys():
            print((u"Le rôle %s n'existe pas !" % role).encode("utf-8"))
            return False
        if role.endswith('-w'):
            print((u"Le rôle %s ne devrait pas être utilisé ! (utilisez %s)")
                   % (role, role[:-2])).encode("utf-8")
            return False
        writable = writable or role in my_roles_w
        ret.add(role)
    
    if not FORCED and not writable:
        if not confirm(u"""Vous vous apprêtez à perdre vos droits d'écritures\
(ROLES ne contient pas %s) sur ce fichier, continuer ?""" %
            ", ".join(my_roles_w)):
            return False
    return list(ret)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="trousseau crans")
    parser.add_argument('-s', '--server', default='default',
        help="Utilisation d'un serveur alternatif (test, backup, etc)")
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
        help="Mode verbeux")
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
        help="Mode silencieux. Cache les message d'erreurs (override --verbose).")
    parser.add_argument('-c', '--clipboard', action='store_true', default=None,
        help="Stocker le mot de passe dans le presse papier")
    parser.add_argument('--no-clip', '--noclip', '--noclipboard', action='store_false', default=None,
        dest='clipboard',
        help="Ne PAS stocker le mot de passe dans le presse papier")
    parser.add_argument('-f', '--force', action='store_true', default=False,
        help="Ne pas demander confirmation")

    # Actions possibles
    action_grp = parser.add_mutually_exclusive_group(required=False)
    action_grp.add_argument('-e', '--edit', action='store_const', dest='action',
        default=show_file, const=edit_file,
        help="Editer (ou créer)")
    action_grp.add_argument('--view', action='store_const', dest='action',
        default=show_file, const=show_file,
        help="Voir le fichier")
    action_grp.add_argument('--remove', action='store_const', dest='action',
        default=show_file, const=remove_file,
        help="Effacer le fichier")
    action_grp.add_argument('-l', '--list', action='store_const', dest='action',
        default=show_file, const=show_files,
        help="Lister les fichiers")
    action_grp.add_argument('--check-keys', action='store_const', dest='action',
        default=show_file, const=my_check_keys,
        help="Vérifier les clés")
    action_grp.add_argument('--update-keys', action='store_const', dest='action',
        default=show_file, const=my_update_keys,
        help="Mettre à jour les clés")
    action_grp.add_argument('--list-roles', action='store_const', dest='action',
        default=show_file, const=show_roles,
        help="Lister les rôles existants")
    action_grp.add_argument('--list-servers', action='store_const', dest='action',
        default=show_file, const=show_servers,
        help="Lister les serveurs")
    action_grp.add_argument('--recrypt-files', action='store_const', dest='action',
        default=show_file, const=recrypt_files,
        help="Rechiffrer les mots de passe. (Avec les mêmes rôles qu'avant, sert à rajouter un lecteur)")

    parser.add_argument('--roles', nargs='?', default=None,
        help="""Liste de roles (séparés par des virgules).
                Avec --edit, le fichier sera chiffré pour exactement ces roles
                (par défaut, tous vos rôles en écriture seront utilisés).
                Avec --recrypt-files, tous les fichiers ayant au moins un de ces roles (et pour lesquels vous avez le droit d'écriture) seront rechiffrés
                (par défaut, tous les fichiers pour lesquels vous avez les droits en écriture sont rechiffrés).""")
    parser.add_argument('fname', nargs='?', default=None,
        help="Nom du fichier à afficher")
    
    parsed = parser.parse_args(sys.argv[1:])
    SERVER = config.servers[parsed.server]
    QUIET = parsed.quiet
    VERB = parsed.verbose and not QUIET
    if parsed.clipboard != None:
        CLIPBOARD = parsed.clipboard
    FORCED = parsed.force
    NEWROLES = parse_roles(parsed.roles)
    
    if NEWROLES != False:
        if parsed.action.func_code.co_argcount == 0:
            parsed.action()
        elif parsed.fname == None:
            if not QUIET:
                print(u"Vous devez fournir un nom de fichier avec cette commande".encode("utf-8"))
                parser.print_help()
            sys.exit(1)
        else:
            parsed.action(parsed.fname)
    
    saveclipboard(restore=True)

