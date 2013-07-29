#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""Gestion centralisée des mots de passe avec chiffrement GPG

Copyright (C) 2010-2013 Cr@ns <roots@crans.org>
Authors : Daniel Stan <daniel.stan@crans.org>
          Vincent Le Gallic <legallic@crans.org>
"""

from __future__ import print_function

# Import builtins
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
import time
import datetime

# Import de la config
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

## Conf qu'il faudrait éliminer en passant ``parsed`` aux fonctions
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

## GPG Definitions
#: Path du binaire gpg
GPG = '/usr/bin/gpg'

#: Paramètres à fournir à gpg en fonction de l'action désirée
GPG_ARGS = {
    'decrypt' : ['-d'],
    'encrypt' : ['--armor', '-es'],
    'receive-keys' : ['--recv-keys'],
    'list-keys' : ['--list-keys', '--with-colons', '--fixed-list-mode',
                   '--with-fingerprint', '--with-fingerprint'], # Ce n'est pas une erreur. Il faut 2 --with-fingerprint pour avoir les fingerprints des subkeys.
    }

#: Mapping (lettre de trustlevel) -> (signification, faut-il faire confiance à la clé)
GPG_TRUSTLEVELS = {
                    u"-" : (u"inconnue (pas de valeur assignée)", False),
                    u"o" : (u"inconnue (nouvelle clé)", False),
                    u"i" : (u"invalide (self-signature manquante ?)", False),
                    u"n" : (u"nulle", False),
                    u"m" : (u"marginale", True),
                    u"f" : (u"entière", True),
                    u"u" : (u"ultime", True),
                    u"r" : (u"révoquée", False),
                    u"e" : (u"expirée", False),
                    u"q" : (u"non définie", False),
                  }

def gpg(command, args=None, verbose=False):
    """Lance gpg pour la commande donnée avec les arguments
    donnés. Renvoie son entrée standard et sa sortie standard."""
    full_command = [GPG]
    full_command.extend(GPG_ARGS[command])
    if args:
        full_command.extend(args)
    if verbose or VERB:
        stderr = sys.stderr
    else:
        stderr = subprocess.PIPE
        full_command.extend(['--debug-level=1'])
    proc = subprocess.Popen(full_command,
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = stderr,
                            close_fds = True)
    if not (verbose or VERB):
        proc.stderr.close()
    return proc.stdin, proc.stdout

def _parse_timestamp(string, canbenone=False):
    """Interprète ``string`` comme un timestamp depuis l'Epoch."""
    if string == u'' and canbenone:
        return None
    return datetime.datetime(*time.localtime(int(string))[:7])

def _parse_pub(data):
    """Interprète une ligne ``pub:``"""
    d = {
        u'trustletter' : data[1],
        u'length' : int(data[2]),
        u'algorithm' : int(data[3]),
        u'longid' : data[4],
        u'signdate' : _parse_timestamp(data[5]),
        u'expiredate' : _parse_timestamp(data[6], canbenone=True),
        u'ownertrustletter' : data[8],
        u'capabilities' : data[11],
        }
    return d

def _parse_uid(data):
    """Interprète une ligne ``uid:``"""
    d = {
        u'trustletter' : data[1],
        u'signdate' : _parse_timestamp(data[5], canbenone=True),
        u'hash' : data[7],
        u'uid' : data[9],
        }
    return d

def _parse_fpr(data):
    """Interprète une ligne ``fpr:``"""
    d = {
        u'fpr' : data[9],
        }
    return d

def _parse_sub(data):
    """Interprète une ligne ``sub:``"""
    d = {
        u'trustletter' : data[1],
        u'length' : int(data[2]),
        u'algorithm' : int(data[3]),
        u'longid' : data[4],
        u'signdate' : _parse_timestamp(data[5]),
        u'expiredate' : _parse_timestamp(data[6], canbenone=True),
        u'capabilities' : data[11],
        }
    return d

#: Functions to parse the recognized fields
GPG_PARSERS = {
    u'pub' : _parse_pub,
    u'uid' : _parse_uid,
    u'fpr' : _parse_fpr,
    u'sub' : _parse_sub,
     }

def _gpg_printdebug(d):
    print("current_pub : %r" % d.get("current_pub", None))
    print("current_sub : %r" % d.get("current_sub", None))

def parse_keys(gpgout, debug=False):
    """Parse l'output d'un listing de clés gpg."""
    ring = {}
    init_value = u"initialize" # Valeur utilisée pour dire "cet objet n'a pas encore été rencontré pendant le parsing"
    current_pub = init_value
    current_sub = init_value
    for line in iter(gpgout.readline, ''):
        # La doc dit que l'output est en UTF-8 «regardless of any --display-charset setting»
        line = line.decode("utf-8")
        line = line.split(":")
        field = line[0]
        if field in GPG_PARSERS.keys():
            if debug:
                print("\nbegin loop. met %s :" % (field))
                _gpg_printdebug(locals())
            try:
                content = GPG_PARSERS[field](line)
            except:
                print("*** FAILED ***")
                print(line)
                raise
            if field == u"pub":
                # Nouvelle clé
                # On sauvegarde d'abord le dernier sub (si il y en a un) dans son pub parent
                if current_sub != init_value:
                    current_pub["subkeys"].append(current_sub)
                # Ensuite on sauve le pub précédent (si il y en a un) dans le ring
                if current_pub != init_value:
                    ring[current_pub[u"fpr"]] = current_pub
                # On place le nouveau comme pub courant
                current_pub = content
                # Par défaut, il n'a ni subkeys, ni uids
                current_pub[u"subkeys"] = []
                current_pub[u"uids"] = []
                # On oublié l'éventuel dernier sub rencontré
                current_sub = init_value
            elif field == u"fpr":
                if current_sub != init_value:
                    # On a lu un sub depuis le dernier pub, donc le fingerprint est celui du dernier sub rencontré
                    current_sub[u"fpr"] = content[u"fpr"]
                else:
                    # Alors c'est le fingerprint du pub
                    current_pub[u"fpr"] = content[u"fpr"]
            elif field == u"uid":
                current_pub[u"uids"].append(content)
            elif field == u"sub":
                # Nouvelle sous-clé
                # D'abord on sauvegarde la précédente (si il y en a une) dans son pub parent
                if current_sub != init_value:
                    current_pub[u"subkeys"].append(current_sub)
                # On place la nouvelle comme sub courant
                current_sub = content
            if debug:
                _gpg_printdebug(locals())
                print("parsed object : %r" % content)
    # À la fin, il faut sauvegarder les derniers (sub, pub) rencontrés,
    # parce que leur sauvegarde n'a pas encore été déclenchée
    if current_sub != init_value:
        current_pub["subkeys"].append(current_sub)
    if current_pub != init_value:
        ring[current_pub[u"fpr"]] = current_pub
    return ring

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

def check_keys(recipients=None, interactive=False, drop_invalid=False):
    """Vérifie les clés, c'est-à-dire, si le mail est présent dans les identités du fingerprint,
       et que la clé est de confiance (et non expirée/révoquée).
       
        * Si ``recipients`` est fourni, vérifie seulement ces recipients.
          Renvoie la liste de ceux qu'on n'a pas droppés.
         * Si ``interactive=True``, demandera confirmation pour dropper un recipient dont la clé est invalide.
         * Sinon, et si ``drop_invalid=True``, droppe les recipients automatiquement.
        * Si rien n'est fourni, vérifie toutes les clés et renvoie juste un booléen disant si tout va bien.
       """
    if QUIET:
        interactive = False
    trusted_recipients = []
    keys = all_keys()
    if recipients is None:
        SPEAK = VERB
    else:
        SPEAK = False
        keys = {u : val for (u, val) in keys.iteritems() if u in recipients}
    if SPEAK:
        print("M : le mail correspond à un uid du fingerprint\nC : confiance OK (inclut la vérification de non expiration).\n")
    _, gpgout = gpg('list-keys')
    localring = parse_keys(gpgout)
    for (recipient, (mail, fpr)) in keys.iteritems():
        failed = u""
        if not fpr is None:
            if SPEAK:
                print((u"Checking %s… " % (mail)).encode("utf-8"), end="")
            key = localring.get(fpr, None)
            # On vérifie qu'on possède la clé…
            if not key is None:
                # …qu'elle correspond au mail…
                if any([u"<%s>" % (mail,) in u["uid"] for u in key["uids"]]):
                    if SPEAK:
                        print("M ", end="")
                    meaning, trustvalue = GPG_TRUSTLEVELS[key["trustletter"]]
                    # … et qu'on lui fait confiance
                    if not trustvalue:
                        failed = u"La confiance en la clé est : %s" % (meaning,)
                    elif SPEAK:
                        print("C ", end="")
                else:
                    failed = u"!! Le fingerprint et le mail ne correspondent pas !"
            else:
                failed = u"Pas (ou trop) de clé avec ce fingerprint."
            if SPEAK:
                print("")
            if failed:
                if not QUIET:
                    print((u"--> Fail on %s:%s\n--> %s" % (mail, fpr, failed)).encode("utf-8"))
                if not recipients is None:
                    # On cherche à savoir si on droppe ce recipient
                    drop = True # par défaut, on le drope
                    if interactive:
                        if not confirm(u"Abandonner le chiffrement pour cette clé ? (Si vous la conservez, il est posible que gpg crashe)"):
                            drop = False # sauf si on a répondu non à "abandonner ?"
                    elif not drop_invalid:
                        drop = False # ou bien si drop_invalid ne nous autorise pas à le dropper silencieusement
                    if not drop:
                        trusted_recipients.append(recipient)
            else:
                trusted_recipients.append(recipient)
    if recipients is None:
        return set(keys.keys()).issubset(trusted_recipients)
    else:
        return trusted_recipients

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

def encrypt(roles, contents, interactive_trust=True, drop_invalid=False):
    """Chiffre le contenu pour les roles donnés"""
    
    allkeys = all_keys()
    recipients = get_recipients_of_roles(roles)
    recipients = check_keys(recipients, interactive=interactive_trust, drop_invalid=drop_invalid)
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

def put_password(name, roles, contents, interactive_trust=True, drop_invalid=False):
    """Dépose le mot de passe après l'avoir chiffré pour les
    destinataires donnés"""
    success, enc_pwd_or_error = encrypt(roles, contents, interactive_trust, drop_invalid)
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

        
def edit_file(fname, interactive_trust=True, drop_invalid=False):
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
        (nfile and ntexte == u'')):                                    # Nouveau fichier créé vide
        print(u"Pas de modification effectuée".encode("utf-8"))
    else:
        ntexte = texte if ntexte == None else ntexte
        success, message = put_password(fname, value['roles'], ntexte, interactive_trust, drop_invalid)
        print(message.encode("utf-8"))

def confirm(text):
    """Demande confirmation, sauf si on est mode ``FORCED``"""
    if FORCED: return True
    while True:
        out = raw_input((text + u' (o/n)').encode("utf-8")).lower()
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

def recrypt_files(interactive_trust=False, drop_invalid=True):
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
            print(u"%s : %s" % (to_put[i]['filename'], results[i][1]))
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
        help="""Rechiffrer les mots de passe.
                (Avec les mêmes rôles que ceux qu'ils avant.
                 Cela sert à mettre à jour les recipients pour qui un password est chiffré)""")

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

