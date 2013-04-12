#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""Configuration du client cranspasswords"""

import os

#: Serveurs distants utilisables,
#: avec la commande distante à exécuter et l'username sur le serveur
servers = {
    'default': {
        'server_cmd': ['/usr/bin/ssh', 'vert.adm.crans.org',\
            '/root/cranspasswords/server'],
        'user' : os.getenv('USER')  # À définir à la main pour les personnes
                                  # n'ayant pas le même login sur leur pc
    },
    'ovh': {
        'server_cmd': ['/usr/bin/ssh', 'ovh.crans.org',\
            '/root/cranspasswords/server'],
        'user' : os.getenv('USER')  # À définir à la main pour les personnes
                                  # n'ayant pas le même login sur leur pc
    }
}
