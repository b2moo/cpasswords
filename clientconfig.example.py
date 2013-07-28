#!/usr/bin/env python
# -*- encoding: utf-8 -*-

""" Configuration du client cranspasswords """

import os

#: Path du binaire ssh sur la machine client
ssh_path = '/usr/bin/ssh'

#: Path du script cranspasswords-server sur le serveur
server_path = '/root/cranspasswords/server'

#: Username utilisé pour se loguer sur le serveur.
#: Par défaut, prend la valeur de l'username sur le client,
#: il faut donc le remplacer pour ceux qui n'ont pas le même username
#: sur le client et le serveur.
username = os.getenv('USER')

#: Liste des serveurs sur lesquels ont peut récupérer des mots de passe.
#: 
#: Sans précision du paramètre --server, la clé ``'default'`` sera utilisée.
#: 
#: * ``'server_cmd'`` : La commande exécutée sur le client pour appeler
#:   le script sur le serveur distant.
#: * ``'user'``: L'username sur le serveur
servers = {
    'default': {
        'server_cmd': [ssh_path, 'vert.adm.crans.org', server_path],
        'user' : username
    },
    'ovh': {
        'server_cmd': [ssh_path, 'ovh.crans.org', server_path],
        'user' : username
    }
}
