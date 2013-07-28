#!/usr/bin/env python
# -*- encoding: utf-8 -*-

""" Configuration Serveur de cranspasswords.

Sont définis ici les utilisateurs et les rôles associés.
Ce fichier est donné à titre d'exemple, mais n'est PAS
utilisé lors du fonctionnement en mode client.

Dans le futur, pourra être remplacé par une connexion ldap.
"""

#: Répertoire de stockage des mots de passe
STORE = '/root/cranspasswords/db/'

#: Ce serveur est-il read-only (on ne peut pas y modifier les mots de passe)
READONLY = False

#: Expéditeur du mail de notification
CRANSP_MAIL = "cranspasswords <root@crans.org>"

#: Destinataire du mail de notification
DEST_MAIL = "root@crans.org"

#: Mapping des utilisateurs et de leurs (mail, fingerprint GPG)
KEYS = {
    'aza-vallina': ('Damien.Aza-Vallina@crans.org', None),
    'becue': ('becue@crans.org', '9AE04D986400E3B67528F4930D442664194974E2'),
    'blockelet': ('blockelet@crans.org', '550A057BC913EA4637D250495314C173AF087A52'),
    'boilard': ('boilard@crans.org', 'E73A648AAB5E81BE38038350C1690AB9C39EB6F4'),
    'cauderlier': ('cauderlier@crans.org', None),
    'chambart': ('pierre.chambart@crans.org', '085D0DFB66EAF9448C42979C43680A46F2530FCE'),
    'dandrimont': ('nicolas.dandrimont@crans.org', '791F12396630DD71FD364375B8E5087766475AAF'),
    'dimino': ('jdimino@dptinfo.ens-cachan.fr', '2C938EAC93A16F8129F807C81E8A30532127F85A'),
    'dstan': ('daniel.stan@crans.org', '90520CFDE846E7651A1B751FBC9BF8456E1C820B'),
    'durand-gasselin': ('adg@crans.org', 'B3EA34ED8A4EA3B5C3E6C04D30F01C448E96ACDA'),
    'glondu': ('Stephane.Glondu@crans.org', '58EB0999C64E897EE894B8037853DA4D49881AD3'),
    'huber': ('olivier.huber@crans.org', '3E9473AF796C530F9C4DE7DB1EF81A95E0DCF376'),
    'iffrig': ('iffrig@crans.org', '26A210E2584208FEF6BE8F3718068DEA354B0045'),
    'lagorce': ('xavier.lagorce@crans.org', '08C26F5AABC5570E5E2F52B39D9D7CE70BF3708E'),
    'lajus': ('lajus@crans.org', None),
    'legallic': ('legallic@crans.org', '4BDD2DC3F10C26B9BC3B0BD93602E1C9A94025B0'),
    'lerisson': ('lerisson@crans.org', None),
    'maioli': ('maioli@crans.org', None),
    'parret-freaud': ('parret-freaud@crans.org', 'A93D3EB37C3669F89C01F9AE13AC8F777D980513'),
    'samir': ('samir@crans.org', 'C7B8823E96E8DC2798970340C86AD2AA41C2B76B'),
    'tvincent': ('vincent.thomas@crans.org', 'DFB04CE4394B1115C587AE101C6BE33AC5C4ACC0'),
#Autogen
    'besson': ('lbesson@ens-cachan.fr', None),#'BF105A8DC75491B9D6EDAC5D01AACDB9C108F8A0',
    'tilquin': ('tilquin@crans.org', None),
    'pvincent': ('pvincent@crans.org', None),
    'pommeret': ('pommeret@crans.org', '8D9C890BD2B783A052DBE71405504FF0CF875FE1'),
    'lasseri': ('lasseri@crans.org', '31EF775095485A1CA4CC7CAAA2A902AE80403321'),
    'moisy-mabille': ('moisy-mabille@crans.org', None),
    'guiraud': ('guiraud@crans.org', '8C8F34952DCBA75CD2963A4C33ECE62B57DA1CD4'),
    'soret': ('soret@crans.org', 'C244290074A0A4A8C05FCA1ACF25D25F17DA8589'),
    'serrano': ('serrano@crans.org', '64ABC0C087EDAA14B79F5F7DEDE22762F030FDC5'),
    'kherouf': ('kherouf@crans.org', None),
    'baste': ('baste@crans.org', None),
    'quelennec': ('quelennec@crans.org', None),
    'grande': ('grande@crans.org', None),
    'gstalter': ('gstalter@crans.org', None),
    'duplouy': ('duplouy@crans.org', None),
    'randazzo': ('randazzo@crans.org', None),
    'epalle': ('epalle@crans.org', None),
    'bonaque': ('bonaque@crans.org', None),
    'kviard': ('kviard@crans.org', None)
}

#: Les variables suivantes sont utilisées pour définir le dictionnaire des
#: rôles.
RTC = [
    "samir"
    ]

#: Liste des usernames des nounous
NOUNOUS = RTC + [
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
    "iffrig",
    "boilard",
    "legallic",
    "pommeret",
    "serrano",
    ]

# Autogen:
#: Liste des usernames des apprentis
APPRENTIS = [
    'grande',
    'bonaque',
    'moisy-mabille',
    'baste',
    'duplouy',
    'besson',
    'pvincent',
    'quelennec',
    'guiraud',
    'kherouf',
    'randazzo',
    'tilquin',
    'lasseri',
    'epalle',
    'soret',
    'gstalter',
    'kviard']

#: Liste des usernames des membres du CA
CA = [
    "becue",
    "duplouy",
    "epalle",
    "guiraud",
    "lajus",
    "lasseri",
    "lerisson",
    "randazzo",
    "soret",
    ]

#: Liste des trésoriers
TRESORERIE = RTC + [
    "soret",
    "guiraud",
    "randazzo",
    ]

#: Les roles utilisés pour savoir qui a le droit le lire/écrire quoi
ROLES = {
    "ca": CA,
    "ca-w": CA,
    "nounous": NOUNOUS,
    "nounous-w": NOUNOUS,
    "apprentis": NOUNOUS + APPRENTIS,
    "apprentis-w": NOUNOUS,
    "tresorerie": TRESORERIE,
    "tresorerie-w": TRESORERIE,
    }
