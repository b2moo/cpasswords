#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os

servers = {
    'default': {
        'server_cmd': ['/usr/bin/ssh', 'vert.adm.crans.org',\
            '/root/cranspasswords/server'],
        'user' : os.getenv('USER')  # À définir à la main pour les personnes
                                  # n'ayant pas le même login sur leur pc
    }
}

