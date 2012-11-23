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

CRANSP_MAIL = "root@crans.org"
""" Expéditeur du mail de notification """

DEST_MAIL = "root@crans.org"
""" Destinataire du mail de notification """


KEYS = {
    "aza-vallina": ("Damien.Aza-Vallina@crans.org", None),
    "dandrimont": ("nicolas.dandrimont@crans.org", "66475AAF"),
    "blockelet": ("blockelet@crans.org", "AF087A52"),
    "chambart": ("pierre.chambart@crans.org", "F2530FCE"),
    "dimino": ("jdimino@dptinfo.ens-cachan.fr", "2127F85A"),
    "durand-gasselin": ("adg@crans.org", "8E96ACDA"),
    "glondu": ("Stephane.Glondu@crans.org", "49881AD3"),
    "huber": ("olivier.huber@crans.org", "E0DCF376"),
    "lagorce": ("xavier.lagorce@crans.org", "0BF3708E"),
    "parret-freaud": ("parret-freaud@crans.org", "7D980513"),
    "tvincent": ("vincent.thomas@crans.org", "C5C4ACC0"),
    "iffrig": ("iffrig@crans.org","5BEC9A2F"),
    "becue": ("becue@crans.org", "194974E2"),
    "dstan": ("daniel.stan@crans.org", "6E1C820B"),
    "samir": ("samir@crans.org", "41C2B76B"),
    "boilard": ("boilard@crans.org", "C39EB6F4"),
    "cauderlier": ("cauderlier@crans.org",None),    #Méchant pas beau
    "maioli": ("maioli@crans.org",None),             #Bis (maybe 9E5026E8)
    "legallic": ("legallic@crans.org", "A94025B0"),
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
