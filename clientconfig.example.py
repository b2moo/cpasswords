#!/usr/bin/env python
# -*- encoding: utf-8 -*-

""" Configuration du client cranspasswords """

import os

#: Pour override le nom si vous voulez renommer la commande
cmd_name = 'cranspasswords'

#: Path du binaire ssh sur la machine client
ssh_path = '/usr/bin/ssh'

#: Path du script ``cmd_name``-server sur le serveur
server_path = '/usr/local/bin/%s-server' % (cmd_name,)

#: Commande à exécuter sur le serveur après y être entré en ssh
distant_cmd = ["sudo", '-n', server_path]

#: Liste des serveurs sur lesquels ont peut récupérer des mots de passe.
#: 
#: Sans précision du paramètre --server, la clé ``'default'`` sera utilisée.
#: 
#: * ``'server_cmd'`` : La commande exécutée sur le client pour appeler
#:   le script sur le serveur distant.
servers = {
    'default': {
        'server_cmd': [ssh_path, 'vert.adm.crans.org'] + distant_cmd,
    },
    # Utile pour tester
    'localhost': {
        'server_cmd': [ssh_path, 'localhost'] + distant_cmd,
    },
    'ovh': {
        'server_cmd': [ssh_path, 'ovh.crans.org'] + distant_cmd,
    }
}
