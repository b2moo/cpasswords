#!/usr/bin/env python
# -*- encoding: utf-8 -*-
""" Configuration Serveur de cranspasswords.
Sont définis ici les utilisateurs et les rôles associés.
Ce fichier est donné à titre d'exemple, mais n'est PAS
utilisé lorsque fonctionnement en mode client.
Dans le futur, sera remplacé par une connexion ldap.
"""

STORE = '/root/cranspasswords/db/'
""" Répertoire de stockage """

READONLY = False
""" Ce serveur est-il read-only (on ne peut pas y modifier les mots de passe) """

CRANSP_MAIL = "cranspasswords <root@crans.org>"
""" Expéditeur du mail de notification """

DEST_MAIL = "root@crans.org"
""" Destinataire du mail de notification """


KEYS = {
    'aza-vallina': None,
    'becue': '0D442664194974E2',
    'blockelet': '5314C173AF087A52',
    'boilard': 'C1690AB9C39EB6F4',
    'cauderlier': None,
    'chambart': '43680A46F2530FCE',
    'dandrimont': 'B8E5087766475AAF',
    'dimino': '1E8A30532127F85A',
    'dstan': 'BC9BF8456E1C820B',
    'durand-gasselin': '30F01C448E96ACDA',
    'glondu': '7853DA4D49881AD3',
    'huber': '1EF81A95E0DCF376',
    'iffrig': '18068DEA354B0045',
    'lagorce': '9D9D7CE70BF3708E',
    'legallic': '3602E1C9A94025B0',
    'maioli': None,
    'parret-freaud': '13AC8F777D980513',
    'samir': 'C86AD2AA41C2B76B',
    'tvincent': '1C6BE33AC5C4ACC0'
    }

# Les variables suivantes sont utilisées pour définir le dictionnaire des
# rôles.
RTC=[
    "iffrig"
    ]
NOUNOUS=RTC+[
    "blockelet",
    "becue",
    "dstan",
    "chambart",
    "dimino",
    "durand-gasselin",
    "glondu",
    "huber",
    "lagorce",
    "parret-freaud",
    "cauderlier",
    "maioli",
    "samir",
    "boilard",
    "legallic",
    ]

CA=[
    "samir",
    "iffrig",
    "cauderlier",
]

## Les vrais rôles !
ROLES = {
    "ca": CA,
    "ca-w": CA,
    "nounous": NOUNOUS,
    "nounous-w": NOUNOUS,
    }
