#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os

servers = {
    'perso': {
        'server_cmd' : [ '/home/dstan/passwords/cranspasswords/cranspasswords-server.py'],
        'user' : 'dstan' },
    'debug': {
        'server_cmd' : ['/usr/bin/ssh', 'localhost', \
            '/home/dstan/crans/cranspasswords/cranspasswords-server.py'],
        'user' : 'dstan' },
    'debug2': {
        'server_cmd':['/usr/bin/ssh', 'vo',\
            '/home/dstan/cranspasswords/cranspasswords-server'],
        'user' : 'dstan'},
    'default': {
        'server_cmd': ['/usr/bin/ssh', 'vert.adm.crans.org',\
            '/root/cranspasswords/cranspasswords-server'],
        'user' : os.getenv('USER')  # À définir à la main pour les personnes
                                  # n'ayant pas le même login sur leur pc
    }
}

