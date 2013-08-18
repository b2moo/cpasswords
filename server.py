#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""Serveur pour cranspasswords"""

from __future__ import print_function

import glob
import os
import pwd
import sys
import json
import smtplib
import datetime
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Même problème que pour le client, il faut bootstraper le nom de la commande
# Pour accéder à la config
cmd_name = os.path.split(sys.argv[0])[1].replace("-server", "")
sys.path.append("/etc/%s/" % (cmd_name,))
import serverconfig

MYUID = pwd.getpwuid(os.getuid())[0]
if MYUID == 'root':
    MYUID = os.environ['SUDO_USER']

## Fonctions internes au serveur

def validate(roles, mode='r'):
    """Vérifie que l'appelant appartient bien aux roles précisés
    Si mode mode='w', recherche un rôle en écriture
    """
    for role in roles:
        if mode == 'w':
            role += '-w'
        if serverconfig.ROLES.has_key(role) and MYUID in serverconfig.ROLES[role]:
            return True
    return False

def getpath(filename, backup=False):
    """Récupère le chemin du fichier ``filename``"""
    return os.path.join(serverconfig.STORE, '%s.%s' % (filename, 'bak' if backup else 'json'))

def writefile(filename, contents):
    """Écrit le fichier avec les bons droits UNIX"""
    os.umask(0077)
    f = open(filename, 'w')
    f.write(contents.encode("utf-8"))
    f.close()

class server_command(object):
    """
    Une instance est un décorateur pour la fonction servant de commande
    externe du même nom"""

    #: nom de la commande
    name = None

    #: fonction wrappée
    decorated = None

    #: (static) dictionnaire name => fonction
    by_name = {}

    #: rajoute un argument en fin de fonction à partir de stdin (si standalone)
    stdin_input = False

    #: Est-ce que ceci a besoin d'écrire ?
    write = False

    def __init__(self, name, stdin_input = False, write=False):
        """
         * ``name`` nom de l'action telle qu'appelée par le client
         * ``stdin_input`` si True, stdin sera lu en mode non-keepalive, et
                           remplira le dernier argument de la commande.
         * ``write`` s'agit-il d'une commande en écriture ?
        """
        self.name = name
        self.stdin_input = stdin_input
        self.write = write
        server_command.by_name[name] = self

    def __call__(self, fun):
        self.decorated = fun
        return fun

## Fonction exposées par le serveur
@server_command('keep-alive')
def keepalive():
    """ Commande permettant de réaliser un tunnel json (un datagramme par ligne)
    Un message entre le client et le serveur consiste en l'échange de dico

    Message du client: {'action': "nom_de_l'action",
                        'args': liste_arguments_passes_a_la_fonction}
    Réponse du serveur: {'status': 'ok',
        'content': retour_de_la_fonction,
    }

    """
    for line in iter(sys.stdin.readline, ''):
        data = json.loads(line.rstrip())
        try:
            # Une action du protocole = de l'ascii
            action = data['action'].encode('ascii')
            content = server_command.by_name[action].decorated(*data['args'])
            status = u'ok'
        except Exception as e:
            status = u'error'
            content = repr(e)
        out = {
            'status': status,
            'content': content,
        }
        print(json.dumps(out, encoding='utf-8'))
        sys.stdout.flush()

@server_command('listroles')
def listroles():
    """Liste des roles existant et de leurs membres.
       Renvoie également un rôle particulier ``"whoami"``, contenant l'username de l'utilisateur qui s'est connecté."""
    d = serverconfig.ROLES
    if d.has_key("whoami"):
        raise ValueError('La rôle "whoami" ne devrait pas exister')
    d["whoami"] = MYUID
    return d

@server_command('listkeys')
def listkeys():
    """Liste les usernames et les (mail, fingerprint) correspondants"""
    return serverconfig.KEYS

@server_command('listfiles')
def listfiles():
    """Liste les fichiers dans l'espace de stockage, et les roles qui peuvent y accéder"""
    os.chdir(serverconfig.STORE)
    
    filenames = glob.glob('*.json')
    files = {}
    for filename in filenames:
        file_dict = json.loads(open(filename).read())
        files[filename[:-5]] = file_dict["roles"]
    return files

@server_command('getfile')
def getfile(filename):
    """Récupère le fichier ``filename``"""
    filepath = getpath(filename)
    try:
        obj = json.loads(open(filepath).read())
        if not validate(obj['roles']):
	        return [False, u"Vous n'avez pas les droits de lecture sur le fichier %s." % filename]
        obj["filename"] = filename
        return [True, obj]
    except IOError:
        return [False, u"Le fichier %s n'existe pas." % filename]
     
@server_command('getfiles', stdin_input=True)
def getfiles(filenames):
    """Récupère plusieurs fichiers, lit la liste des filenames demandés sur stdin"""
    return [getfile(f) for f in filenames]

# TODO ça n'a rien à faire là, à placer plus haut dans le code
def _putfile(filename, roles, contents):
    """Écrit ``contents`` avec les roles ``roles`` dans le fichier ``filename``"""
    gotit, old = getfile(filename)
    if not gotit:
        old = u"[Création du fichier]"
        pass
    else:
        oldroles = old['roles']
        if not validate(oldroles, 'w'):
            return [False, u"Vous n'avez pas le droit d'écriture sur %s." % filename]
    
    corps = u"Le fichier %s a été modifié par %s." % (filename, MYUID)
    backup(corps, filename, old)
    notification(u"Modification de %s" % filename, corps, filename, old)
    
    filepath = getpath(filename)
    writefile(filepath, json.dumps({'roles': roles, 'contents': contents}))
    return [True, u"Modification effectuée."]

@server_command('putfile', stdin_input=True, write=True)
def putfile(filename, parsed_stdin):
    """Écrit le fichier ``filename`` avec les données reçues sur stdin."""
    try:
        roles = parsed_stdin['roles']
        contents = parsed_stdin['contents']
    except KeyError:
        return [False, u"Entrée invalide"]
    return _putfile(filename, roles, contents)

@server_command('putfiles', stdin_input=True, write=True)
def putfiles(parsed_stdin):
    """Écrit plusieurs fichiers. Lit les filenames sur l'entrée standard avec le reste."""
    results = []
    for fichier in parsed_stdin:
        try:
            filename = fichier['filename']
            roles = fichier['roles']
            contents = fichier['contents']
        except KeyError:
            results.append([False, u"Entrée invalide"])
        else:
            results.append(_putfile(filename, roles, contents))
    return results

@server_command('rmfile', write=True)
def rmfile(filename):
    """Supprime le fichier filename après avoir vérifié les droits sur le fichier"""
    gotit, old = getfile(filename)
    if not gotit:
        return old # contient le message d'erreur
    roles = old['roles']
    if validate(roles, 'w'):
        corps = u"Le fichier %s a été supprimé par %s." % (filename, MYUID)
        backup(corps, filename, old)
        notification(u"Suppression de %s" % filename, corps, filename, old)
        os.remove(getpath(filename))
    else:
        return u"Vous n'avez pas les droits d'écriture sur le fichier %s." % filename
    return u"Suppression effectuée"


# TODO monter plus haut
def backup(corps, fname, old):
    """Backupe l'ancienne version du fichier"""
    os.umask(0077)
    back = open(getpath(fname, backup=True), 'a')
    back.write(json.dumps(old))
    back.write('\n')
    back.write((u'* %s: %s\n' % (str(datetime.datetime.now()), corps)).encode("utf-8"))
    back.close()

# TODO monter plus haut
def notification(subject, corps, fname, old):
    """Envoie par mail une notification de changement de fichier"""
    conn = smtplib.SMTP('localhost')
    frommail = serverconfig.CRANSP_MAIL
    tomail = serverconfig.DEST_MAIL
    msg = MIMEMultipart(_charset="utf-8")
    msg['Subject'] = subject
    msg['X-Mailer'] = serverconfig.cmd_name.decode()
    msg['From'] = serverconfig.CRANSP_MAIL
    msg['To'] = serverconfig.DEST_MAIL
    msg.preamble = u"%s report" % (serverconfig.cmd_name.decode(),)
    info = MIMEText(corps +
        u"\nLa version précédente a été sauvegardée." +
        u"\n\nModification effectuée sur %s." % socket.gethostname() +
        u"\n\n-- \nCranspasswords.py", _charset="utf-8")
    msg.attach(info)
    conn.sendmail(frommail, tomail, msg.as_string())
    conn.quit()

if __name__ == "__main__":
    argv = sys.argv[0:]
    command_name = argv[1]

    command = server_command.by_name[command_name]
    if serverconfig.READONLY and command.write:
        raise IOError("Ce serveur est read-only.")

    args = argv[2:]
    # On veut des unicode partout
    args = [ s.decode('utf-8') for s in args ]
    if command.stdin_input:
        args.append(json.loads(sys.stdin.read()))
    answer = command.decorated(*args)
    if answer is not None:
        print(json.dumps(answer))
