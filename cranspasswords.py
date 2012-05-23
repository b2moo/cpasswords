#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""cranspasswords: gestion des mots de passe du Cr@ns"""

import sys
import subprocess
import json

######
## GPG Definitions

GPG = '/usr/bin/gpg'
GPG_ARGS = {
    'decrypt': ['-d'],
    'encrypt': ['--armor', '-es'],
    'fingerprint': ['--fingerprint'],
    'receive-keys': ['--recv-keys'],
    }

def gpg(command, args = None):
    """Lance gpg pour la commande donnée avec les arguments
    donnés. Renvoie son entrée standard et sa sortie standard."""
    full_command = [GPG]
    full_command.extend(GPG_ARGS[command])
    if args:
        full_command.extend(args)
    proc = subprocess.Popen(full_command,
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = sys.stderr,
                            close_fds = True)
    return proc.stdin, proc.stdout

######
## Remote commands

SSH = '/usr/bin/ssh'
SSH_HOST = 'localhost'
REMOTE_COMMAND = ['/home/nicolasd/cranspasswords-server.py']

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
            if "<%s>" % mail.lower() not in stdout.read().lower():
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
    return stdout.read()

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
    return put_file(name, roles, enc_pwd)

def get_password(name):
    """Récupère le mot de passe donné par name"""
    remotefile = get_file(name)
    return decrypt(remotefile['contents'])


