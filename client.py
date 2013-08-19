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
import copy

# Import de la config
envvar = "CRANSPASSWORDS_CLIENT_CONFIG_DIR"
try:
    # Oui, le nom de la commande est dans la config, mais on n'a pas encore accès à la config
    bootstrap_cmd_name = os.path.split(sys.argv[0])[1]
    sys.path.append(os.path.expanduser("~/.config/%s/" % (bootstrap_cmd_name,)))
    import clientconfig as config
except ImportError:
    ducktape_display_error = sys.stderr.isatty() and not any([opt in sys.argv for opt in ["-q", "--quiet"]])
    envspecified = os.getenv(envvar, None)
    if envspecified is None:
        if ducktape_display_error:
            sys.stderr.write(u"Va lire le fichier README.\n".encode("utf-8"))
        sys.exit(1)
    else:
        # On a spécifié à la main le dossier de conf
        try:
            sys.path.append(envspecified)
            import clientconfig as config
        except ImportError:
            if ducktape_display_error:
                sys.stderr.write(u"%s est spécifiée, mais aucune config pour le client ne peut être importée." % (envvar))
                sys.exit(1)

#: Pattern utilisé pour détecter la ligne contenant le mot de passe dans les fichiers
pass_regexp = re.compile('[\t ]*pass(?:word)?[\t ]*:[\t ]*(.*)\r?\n?$',
        flags=re.IGNORECASE)

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
                    u"n" : (u"nulle (il ne faut pas faire confiance à cette clé)", False),
                    u"m" : (u"marginale (pas assez de lien de confiance vers cette clé)", False),
                    u"f" : (u"entière (clé dans le réseau de confiance)", True),
                    u"u" : (u"ultime (c'est probablement ta clé)", True),
                    u"r" : (u"révoquée", False),
                    u"e" : (u"expirée", False),
                    u"q" : (u"non définie", False),
                  }

def gpg(options, command, args=None):
    """Lance gpg pour la commande donnée avec les arguments
    donnés. Renvoie son entrée standard et sa sortie standard."""
    full_command = [GPG]
    full_command.extend(GPG_ARGS[command])
    if args:
        full_command.extend(args)
    if options.verbose:
        stderr = sys.stderr
    else:
        stderr = subprocess.PIPE
        full_command.extend(['--debug-level=1'])
    proc = subprocess.Popen(full_command,
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = stderr,
                            close_fds = True)
    if not options.verbose:
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

    def __call__(self, *args, **kwargs):
        """Attention ! On peut fournir des paramètres, mais comme on mémorise pour la prochaine fois,
           si on rappelle avec des paramètres différents, on aura quand même la même réponse.
           Pour l'instant, on s'en fiche puisque les paramètres ne changent pas d'un appel au suivant,
           mais il faudra s'en préoccuper si un jour on veut changer le comportement."""
        if self.val == None:
            self.val = self.f(*args, **kwargs)
        # On évite de tout deepcopier. Typiquement, un subprocess.Popen
        # ne devrait pas l'être (comme dans get_keep_alive_connection)
        if type(self.val) in [dict, list]:
            return copy.deepcopy(self.val)
        else:
            return self.val


######
## Remote commands

def remote_proc(options, command, arg=None):
    """
    Fabrique un process distant pour communiquer avec le serveur.
    Cela consiste à lancer une commande (indiquée dans la config)
    qui va potentiellement lancer ssh.
    ``command`` désigne l'action à envoyer au serveur
    ``arg`` est une chaîne (str) accompagnant la commande en paramètre
    ``options`` contient la liste usuelle d'options
    """
    full_command = list(options.serverdata['server_cmd'])
    full_command.append(command)
    if arg:
        full_command.append(arg)

    if options.verbose and not options.quiet:
        print("Running command %s ..." % " ".join(full_command))

    proc = subprocess.Popen(full_command,
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = sys.stderr,
                            close_fds = True)
    return proc

@simple_memoize
def get_keep_alive_connection(options):
    """Fabrique un process parlant avec le serveur suivant la commande
    'keep-alive'. On utilise une fonction séparée pour cela afin
    de memoizer le résultat, et ainsi utiliser une seule connexion"""
    proc = remote_proc(options, 'keep-alive', None)
    atexit.register(proc.stdin.close)
    return proc

def remote_command(options, command, arg=None, stdin_contents=None):
    """Exécute la commande distante, et retourne la sortie de cette
    commande"""
    detail = options.verbose and not options.quiet
    keep_alive = options.serverdata.get('keep-alive', False)
    
    if keep_alive:
        conn = get_keep_alive_connection(options)
        args = filter(None, [arg, stdin_contents])
        msg = {u'action': unicode(command), u'args': args }
        conn.stdin.write('%s\n' % json.dumps(msg))
        conn.stdin.flush()
        raw_out = conn.stdout.readline()
    else:
        proc = remote_proc(options, command, arg)
        if stdin_contents is not None:
            proc.stdin.write(json.dumps(stdin_contents))
            proc.stdin.close()
        ret = proc.wait()
        raw_out = proc.stdout.read()
        if ret != 0:
            if not options.quiet:
                print((u"Mauvais code retour côté serveur, voir erreur " +
                       u"ci-dessus").encode('utf-8'),
                      file=sys.stderr)
                if detail:
                    print("raw_output: %s" % raw_out)
            sys.exit(ret)
    try:
        answer = json.loads(raw_out.strip())
    except ValueError:
        if not options.quiet:
            print(u"Impossible de parser le résultat".encode('utf-8'),
                  file=sys.stderr)
            if detail:
                print("raw_output: %s" % raw_out)
            sys.exit(42)
    if not keep_alive:
        return answer
    else:
        try:
            if answer[u'status'] != u'ok':
                raise KeyError('Bad answer status')
            return answer[u'content']
        except KeyError:
            if not options.quiet:
                print(u"Réponse erronée du serveur".encode('utf-8'),
                    file=sys.stderr)
            if detail:
                print("answer: %s" % repr(answer))
            sys.exit(-1)


@simple_memoize
def all_keys(options):
    """Récupère les clés du serveur distant"""
    return remote_command(options, "listkeys")

@simple_memoize
def all_roles(options):
    """Récupère les roles du serveur distant"""
    return remote_command(options, "listroles")

@simple_memoize
def all_files(options):
    """Récupère les fichiers du serveur distant"""
    return remote_command(options, "listfiles")

def get_files(options, filenames):
    """Récupère le contenu des fichiers distants"""
    return remote_command(options, "getfiles", stdin_contents=filenames)

def put_files(options, files):
    """Dépose les fichiers sur le serveur distant"""
    return remote_command(options, "putfiles", stdin_contents=files)

def rm_file(filename):
    """Supprime le fichier sur le serveur distant"""
    return remote_command(options, "rmfile", filename)

@simple_memoize
def get_my_roles(options):
    """Retourne la liste des rôles de l'utilisateur, et également la liste des rôles dont il possède le role-w."""
    allroles = all_roles(options)
    distant_username = allroles.pop("whoami")
    my_roles = [r for (r, users) in allroles.iteritems() if distant_username in users]
    my_roles_w = [r[:-2] for r in my_roles if r.endswith("-w")]
    return (my_roles, my_roles_w)

def gen_password():
    """Génère un mot de passe aléatoire"""
    random.seed(datetime.datetime.now().microsecond)
    chars = string.letters + string.digits + '/=+*'
    length = 15
    return u''.join([random.choice(chars) for _ in xrange(length)])

######
## Local commands

def update_keys(options):
    """Met à jour les clés existantes"""
    
    keys = all_keys(options)
    
    _, stdout = gpg(options, "receive-keys", [key for _, key in keys.values() if key])
    return stdout.read().decode("utf-8")

def _check_encryptable(key):
    """Vérifie qu'on peut chiffrer un message pour ``key``.
       C'est-à-dire, que la clé est de confiance (et non expirée).
       Puis qu'on peut chiffrer avec, ou qu'au moins une de ses subkeys est de chiffrement (capability e)
       et est de confiance et n'est pas expirée"""
    # Il faut que la clé soit dans le réseau de confiance…
    meaning, trustvalue = GPG_TRUSTLEVELS[key[u"trustletter"]]
    if not trustvalue:
        return u"La confiance en la clé est : %s" % (meaning,)
    # …et qu'on puisse chiffrer avec…
    if u"e" in key[u"capabilities"]:
        # …soit directement…
        return u""
    # …soit avec une de ses subkeys
    esubkeys = [sub for sub in key[u"subkeys"] if u"e" in sub[u"capabilities"]]
    if len(esubkeys) == 0:
        return u"La clé principale de permet pas de chiffrer et auncune sous-clé de chiffrement."
    if any([GPG_TRUSTLEVELS[sub[u"trustletter"]][1] for sub in esubkeys]):
        return u""
    else:
        return u"Aucune sous clé de chiffrement n'est de confiance et non expirée."

def check_keys(options, recipients=None, quiet=False):
    """Vérifie les clés, c'est-à-dire, si le mail est présent dans les identités du fingerprint,
       et que la clé est de confiance (et non expirée/révoquée).
       
        * Si ``recipients`` est fourni, vérifie seulement ces recipients.
          Renvoie la liste de ceux qu'on n'a pas droppés.
         * Si ``options.force=False``, demandera confirmation pour dropper un recipient dont la clé est invalide.
         * Sinon, et si ``options.drop_invalid=True``, droppe les recipients automatiquement.
        * Si rien n'est fourni, vérifie toutes les clés et renvoie juste un booléen disant si tout va bien.
       """
    trusted_recipients = []
    keys = all_keys(options)
    if recipients is None:
        speak = options.verbose and not options.quiet
    else:
        speak = False
        keys = {u : val for (u, val) in keys.iteritems() if u in recipients}
    if speak:
        print("M : le mail correspond à un uid du fingerprint\nC : confiance OK (inclut la vérification de non expiration).\n")
    _, gpgout = gpg(options, 'list-keys')
    localring = parse_keys(gpgout)
    for (recipient, (mail, fpr)) in keys.iteritems():
        failed = u""
        if not fpr is None:
            if speak:
                print((u"Checking %s… " % (mail)).encode("utf-8"), end="")
            key = localring.get(fpr, None)
            # On vérifie qu'on possède la clé…
            if not key is None:
                # …qu'elle correspond au mail…
                if any([u"<%s>" % (mail,) in u["uid"] for u in key["uids"]]):
                    if speak:
                        print("M ", end="")
                    # … et qu'on peut raisonnablement chiffrer pour lui
                    failed = _check_encryptable(key)
                    if not failed and speak:
                        print("C ", end="")
                else:
                    failed = u"!! Le fingerprint et le mail ne correspondent pas !"
            else:
                failed = u"Pas (ou trop) de clé avec ce fingerprint."
            if speak:
                print("")
            if failed:
                if not options.quiet:
                    print((u"--> Fail on %s:%s\n--> %s" % (mail, fpr, failed)).encode("utf-8"))
                if not recipients is None:
                    # On cherche à savoir si on droppe ce recipient
                    message = u"Abandonner le chiffrement pour cette clé ? (Si vous la conservez, il est posible que gpg crashe)"
                    if confirm(options, message):
                        drop = True # si on a répondu oui à "abandonner ?", on droppe
                    elif options.drop_invalid and options.force:
                        drop = True # ou bien si --drop-invalid avec --force nous autorisent à dropper silencieusement
                    else:
                        drop = False # Là, on droppe pas
                    if not drop:
                        trusted_recipients.append(recipient)
                    else:
                        if not options.quiet:
                            print(u"Droppe la clé %s:%s" % (fpr, recipient))
            else:
                trusted_recipients.append(recipient)
    if recipients is None:
        return set(keys.keys()).issubset(trusted_recipients)
    else:
        return trusted_recipients

def get_recipients_of_roles(options, roles):
    """Renvoie les destinataires d'une liste de rôles"""
    recipients = set()
    allroles = all_roles(options)
    allroles.pop("whoami")
    for role in roles:
        for recipient in allroles[role]:
            recipients.add(recipient)
    return recipients

def get_dest_of_roles(options, roles):
    """Renvoie la liste des "username : mail (fingerprint)" """
    allkeys = all_keys(options)
    return [u"%s : %s (%s)" % (rec, allkeys[rec][0], allkeys[rec][1])
               for rec in get_recipients_of_roles(options, roles) if allkeys[rec][1]]

def encrypt(options, roles, contents):
    """Chiffre le contenu pour les roles donnés"""
    
    allkeys = all_keys(options)
    recipients = get_recipients_of_roles(options, roles)
    recipients = check_keys(options, recipients=recipients, quiet=True)
    fpr_recipients = []
    for recipient in recipients:
        fpr = allkeys[recipient][1]
        if fpr:
            fpr_recipients.append("-r")
            fpr_recipients.append(fpr)
    
    stdin, stdout = gpg(options, "encrypt", fpr_recipients)
    stdin.write(contents.encode("utf-8"))
    stdin.close()
    out = stdout.read().decode("utf-8")
    if out == '':
        return [False, u"Échec de chiffrement"]
    else:
        return [True, out]

def decrypt(options, contents):
    """Déchiffre le contenu"""
    stdin, stdout = gpg(options, "decrypt")
    stdin.write(contents.encode("utf-8"))
    stdin.close()
    return stdout.read().decode("utf-8")

def put_password(options, roles, contents):
    """Dépose le mot de passe après l'avoir chiffré pour les
    destinataires dans ``roles``."""
    success, enc_pwd_or_error = encrypt(options, roles, contents)
    if success:
        enc_pwd = enc_pwd_or_error
        return put_files(options, [{'filename' : options.fname, 'roles' : roles, 'contents' : enc_pwd}])[0]
    else:
        error = enc_pwd_or_error
        return [False, error]

######
## Interface

NEED_FILENAME = []

def need_filename(f):
    """Décorateur qui ajoutera la fonction à la liste des fonctions qui attendent un filename."""
    NEED_FILENAME.append(f)
    return f

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

def show_files(options):
    """Affiche la liste des fichiers disponibles sur le serveur distant"""
    print(u"Liste des fichiers disponibles :".encode("utf-8"))
    my_roles, _ = get_my_roles(options)
    files = all_files(options)
    keys = files.keys()
    keys.sort()
    for fname in keys:
        froles = files[fname]
        access = set(my_roles).intersection(froles) != set([])
        print((u" %s %s (%s)" % ((access and '+' or '-'), fname, ", ".join(froles))).encode("utf-8"))
    print((u"""--Mes roles: %s""" % (", ".join(my_roles),)).encode("utf-8"))
    
def show_roles(options):
    """Affiche la liste des roles existants"""
    print(u"Liste des roles disponibles".encode("utf-8"))
    allroles =  all_roles(options)
    for (role, usernames) in allroles.iteritems():
        if not role.endswith('-w'):
            print((u" * %s : %s" % (role, ", ".join(usernames))).encode("utf-8"))

def show_servers(options):
    """Affiche la liste des serveurs disponibles"""
    print(u"Liste des serveurs disponibles".encode("utf-8"))
    for server in config.servers.keys():
        print((u" * " + server).encode("utf-8"))

def saveclipboard(restore=False, old_clipboard=None):
    """Enregistre le contenu du presse-papier. Le rétablit si ``restore=True``"""
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
    return old_clipboard

def clipboard(texte):
    """Place ``texte`` dans le presse-papier en mémorisant l'ancien contenu."""
    old_clipboard = saveclipboard()
    proc =subprocess.Popen(['xclip', '-selection', 'clipboard'],\
        stdin=subprocess.PIPE, stdout=sys.stdout, stderr=sys.stderr)
    proc.stdin.write(texte.encode("utf-8"))
    proc.stdin.close()
    return old_clipboard

@need_filename
def show_file(options):
    """Affiche le contenu d'un fichier"""
    fname = options.fname
    gotit, value = get_files(options, [fname])[0]
    if not gotit:
        if not options.quiet:
            print(value.encode("utf-8")) # value contient le message d'erreur
        return
    passfile = value
    (sin, sout) = gpg(options, 'decrypt')
    sin.write(passfile['contents'].encode("utf-8"))
    sin.close()
    texte = sout.read().decode("utf-8")
    ntexte = u""
    hidden = False  # Est-ce que le mot de passe a été caché ?
    lines = texte.split('\n')
    old_clipboard = None
    for line in lines:
        catchPass = None
        # On essaie de trouver le pass pour le cacher dans le clipboard
        # si ce n'est déjà fait et si c'est voulu
        if not hidden and options.clipboard:
            catchPass = pass_regexp.match(line)
        if catchPass != None:
            hidden = True
            # On met le mdp dans le clipboard en mémorisant sont ancien contenu
            old_clipboard = clipboard(catchPass.group(1))
            # Et donc on override l'affichage
            line = u"[Le mot de passe a été mis dans le presse papier]"
        ntexte += line + '\n'
    showbin = "cat" if hidden else "less"
    proc = subprocess.Popen([showbin], stdin=subprocess.PIPE)
    out = proc.stdin
    raw = u"Fichier %s:\n\n%s-----\nVisible par: %s\n" % (fname, ntexte, ','.join(passfile['roles']))
    out.write(raw.encode("utf-8"))
    out.close()
    os.waitpid(proc.pid, 0)
    # Repope ancien pass
    if options.clipboard:
        saveclipboard(restore=True, old_clipboard=old_clipboard)

@need_filename
def edit_file(options):
    """Modifie/Crée un fichier"""
    fname = options.fname
    gotit, value = get_files(options, [fname])[0]
    nfile = False
    annotations = u""
    if not gotit and not u"pas les droits" in value:
        nfile = True
        if not options.quiet:
            print(u"Fichier introuvable".encode("utf-8"))
        if not confirm(options, u"Créer fichier ?"):
            return
        annotations += u"""Ceci est un fichier initial contenant un mot de passe
aléatoire, pensez à rajouter une ligne "login: ${login}"
Enregistrez le fichier vide pour annuler.\n"""
        texte = u"pass: %s\n" % gen_password()
        if options.roles == []:
            if not options.quiet:
                print(u"Vous ne possédez aucun rôle en écriture ! Abandon.".encode("utf-8"))
            return
        passfile = {'roles' : options.roles}
    elif not gotit:
        if not options.quiet:
            print(value.encode("utf-8")) # value contient le message d'erreur
        return
    else:
        passfile = value
        (sin, sout) = gpg(options, 'decrypt')
        sin.write(passfile['contents'].encode("utf-8"))
        sin.close()
        texte = sout.read().decode("utf-8")
    # On peut vouloir chiffrer un fichier sans avoir la possibilité de le lire dans le futur
    # Mais dans ce cas on préfère demander confirmation
    my_roles, _ = get_my_roles(options)
    if not options.force and set(options.roles).intersection(my_roles) == set():
        message = u"""Vous vous apprêtez à perdre vos droits de lecture (ROLES ne contient rien parmi : %s) sur ce fichier, continuer ?"""
        message = message % (", ".join(my_roles),)
        if not confirm(options, message):
            sys.exit(2)
    # On récupère les nouveaux roles si ils ont été précisés, sinon on garde les mêmes
    passfile['roles'] = options.roles or passfile['roles']
    
    annotations += u"""Ce fichier sera chiffré pour les rôles suivants :\n%s\n
C'est-à-dire pour les utilisateurs suivants :\n%s""" % (
           ', '.join(passfile['roles']),
           '\n'.join(' %s' % rec for rec in get_dest_of_roles(options, passfile['roles']))
        )
    
    ntexte = editor(texte, annotations)
    
    if ((not nfile and ntexte in [u'', texte]              # pas nouveau, vidé ou pas modifié
         and set(options.roles) == set(passfile['roles'])) # et on n'a même pas touché à ses rôles,
        or (nfile and ntexte == u'')):                     # ou alors on a créé un fichier vide.
        message = u"Pas de modification à enregistrer.\n"
        message += u"Si ce n'est pas un nouveau fichier, il a été vidé ou n'a pas été modifié (même pas ses rôles).\n"
        message += u"Si c'est un nouveau fichier, vous avez tenté de le créer vide."
        if not options.quiet:
            print(message.encode("utf-8"))
    else:
        ntexte = texte if ntexte == None else ntexte
        success, message = put_password(options, passfile['roles'], ntexte)
        print(message.encode("utf-8"))

def confirm(options, text):
    """Demande confirmation, sauf si on est mode ``--force``"""
    if options.force:
        return True
    while True:
        out = raw_input((text + u' (o/n)').encode("utf-8")).lower()
        if out == 'o':
            return True
        elif out == 'n':
            return False

@need_filename
def remove_file(options):
    """Supprime un fichier"""
    fname = options.fname
    if not confirm(options, u'Êtes-vous sûr de vouloir supprimer %s ?' % (fname,)):
        return
    message = rm_file(fname)
    print(message.encode("utf-8"))


def my_check_keys(options):
    """Vérifie les clés et affiche un message en fonction du résultat"""
    print(u"Vérification que les clés sont valides (uid correspondant au login) et de confiance.")
    print((check_keys(options) and u"Base de clés ok" or u"Erreurs dans la base").encode("utf-8"))

def my_update_keys(options):
    """Met à jour les clés existantes et affiche le résultat"""
    print(update_keys(options).encode("utf-8"))

def recrypt_files(options):
    """Rechiffre les fichiers.
       Ici, la signification de ``options.roles`` est : on ne veut rechiffrer que les fichiers qui ont au moins un de ces roles.
       """
    rechiffre_roles = options.roles
    _, my_roles_w = get_my_roles(options)
    if rechiffre_roles == None:
        # Sans précisions, on prend tous les roles qu'on peut
        rechiffre_roles = my_roles_w
    
    # La liste des fichiers
    allfiles = all_files(options)
    # On ne demande que les fichiers qui ont au moins un role dans ``options.roles``
    # et dans lesquels on peut écrire
    askfiles = [filename for (filename, fileroles) in allfiles.iteritems()
                         if set(fileroles).intersection(options.roles) != set()
                         and set(fileroles).intersection(my_roles_w) != set()]
    files = get_files(options, askfiles)
    # Au cas où on aurait échoué à récupérer ne serait-ce qu'un de ces fichiers,
    # on affiche le message d'erreur correspondant et on abandonne.
    for (success, message) in files:
        if not success:
            if not options.quiet:
                print(message.encode("utf-8"))
            return
    # On informe l'utilisateur et on demande confirmation avant de rechiffrer
    # Si il a précisé --force, on ne lui demandera rien.
    filenames = ", ".join(askfiles)
    message = u"Vous vous apprêtez à rechiffrer les fichiers suivants :\n%s" % filenames
    if not confirm(options, message + u"\nConfirmer"):
        sys.exit(2)
    # On rechiffre
    to_put = [{'filename' : f['filename'],
               'roles' : f['roles'],
               'contents' : encrypt(options, f['roles'], decrypt(options, f['contents']))}
              for [success, f] in files]
    if to_put:
        if not options.quiet:
            print((u"Rechiffrement de %s" % (", ".join([f['filename'] for f in to_put]))).encode("utf-8"))
        results = put_files(options, to_put)
        # On affiche les messages de retour
        if not options.quiet:
            for i in range(len(results)):
                print(u"%s : %s" % (to_put[i]['filename'], results[i][1]))
    else:
        if not options.quiet:
            print(u"Aucun fichier n'a besoin d'être rechiffré".encode("utf-8"))

def parse_roles(options):
    """Interprête la liste de rôles fournie par l'utilisateur.
       Si il n'en a pas fourni, on considère qu'il prend tous ceux pour lesquels il a le -w.
       
       Renvoie ``False`` si au moins un de ces rôles pose problème.
       
       poser problème, c'est :
        * être un role-w (il faut utiliser le role sans le w)
        * ne pas exister dans la config du serveur
    
    """
    strroles = options.roles
    allroles = all_roles(options)
    _, my_roles_w = get_my_roles(options)
    if strroles == None:
        # L'utilisateur n'a rien donné, on lui donne les rôles (non -w) dont il possède le -w
        return my_roles_w
    ret = set()
    for role in strroles.split(','):
        if role not in allroles.keys():
            if not options.quiet:
                print((u"Le rôle %s n'existe pas !" % role).encode("utf-8"))
            sys.exit(1)
        if role.endswith('-w'):
            if not options.quiet:
                print((u"Le rôle %s ne devrait pas être utilisé ! (utilisez %s)")
                       % (role, role[:-2])).encode("utf-8")
            sys.exit(1)
        ret.add(role)
    return list(ret)

def insult_on_nofilename(options, parser):
    """Insulte (si non quiet) et quitte si aucun nom de fichier n'a été fourni en commandline."""
    if options.fname == None:
        if not options.quiet:
            print(u"Vous devez fournir un nom de fichier avec cette commande".encode("utf-8"))
            parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gestion de mots de passe partagés grâce à GPG.")
    parser.add_argument('-s', '--server', default='default',
        help="Utilisation d'un serveur alternatif (test, backup, etc)")
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
        help="Mode verbeux")
    parser.add_argument('--drop-invalid', action='store_true', default=False,
        dest='drop_invalid',
        help="Combiné avec --force, droppe les clés en lesquelles on n'a pas confiance sans demander confirmation.")
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
        help="Mode silencieux. Cache les message d'erreurs (override --verbose et --interactive).")
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
    
    # On parse les options fournies en commandline
    options = parser.parse_args(sys.argv[1:])
    
    ## On calcule les options qui dépendent des autres.
    ## C'est un peu un hack, peut-être que la méthode propre serait de surcharger argparse.ArgumentParser
    ## et argparse.Namespace, mais j'ai pas réussi à comprendre commenr m'en sortir.
    # ** Presse papier **
    # Si l'utilisateur n'a rien dit (ni option --clipboard ni --noclipboard),
    # on active le clipboard par défaut, à la condition
    # que xclip existe et qu'il a un serveur graphique auquel parler.
    if options.clipboard is None:
        options.clipboard = bool(os.getenv('DISPLAY')) and os.path.exists('/usr/bin/xclip')
    # On récupère les données du serveur à partir du nom fourni
    options.serverdata = config.servers[options.server]
    # Attention à l'ordre pour interactive
    #  --quiet override --verbose
    if options.quiet:
        options.verbose = False
    # On parse les roles fournis, et il doivent exister, ne pas être -w…
    # parse_roles s'occupe de ça
    # NB : ça nécessite de se connecter au serveur, or, pour show_servers on n'en a pas besoin
    # Il faudrait ptêtre faire ça plus proprement, en attendant, je ducktape.
    if options.action != show_servers:
        options.roles = parse_roles(options)
    
    # Si l'utilisateur a demandé une action qui nécessite un nom de fichier,
    # on vérifie qu'il a bien fourni un nom de fichier.
    if options.action in NEED_FILENAME:
        insult_on_nofilename(options, parser)
    
    # On exécute l'action demandée
    options.action(options)
