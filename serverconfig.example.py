#!/usr/bin/env python
# -*- encoding: utf-8 -*-

""" Configuration Serveur de cranspasswords.

Sont définis ici les utilisateurs et les rôles associés.
Ce fichier est donné à titre d'exemple, mais n'est PAS
utilisé lors du fonctionnement en mode client.

Dans le futur, pourra être remplacé par une connexion ldap.
"""

#: Pour override le nom si vous voulez renommer la commande
cmd_name = 'cranspasswords'

#: Répertoire de stockage des mots de passe
STORE = '/var/lib/%s/db/' % (cmd_name,)

#: Ce serveur est-il read-only (on ne peut pas y modifier les mots de passe)
READONLY = False

#: Expéditeur du mail de notification
CRANSP_MAIL = u"%s <root@crans.org>" % (cmd_name,)

#: Destinataire du mail de notification
DEST_MAIL = u"root@crans.org"

#: Mapping des utilisateurs et de leurs (mail, fingerprint GPG)
KEYS = {
    u'aza-vallina': (u'Damien.Aza-Vallina@crans.org', None),
    u'becue': (u'becue@crans.org', u'9AE04D986400E3B67528F4930D442664194974E2'),
    u'blockelet': (u'blockelet@crans.org', u'550A057BC913EA4637D250495314C173AF087A52'),
    u'boilard': (u'boilard@crans.org', u'E73A648AAB5E81BE38038350C1690AB9C39EB6F4'),
    u'cauderlier': (u'cauderlier@crans.org', None),
    u'chambart': (u'pierre.chambart@crans.org', u'085D0DFB66EAF9448C42979C43680A46F2530FCE'),
    u'dandrimont': (u'nicolas.dandrimont@crans.org', u'791F12396630DD71FD364375B8E5087766475AAF'),
    u'dimino': (u'jdimino@dptinfo.ens-cachan.fr', u'2C938EAC93A16F8129F807C81E8A30532127F85A'),
    u'dstan': (u'daniel.stan@crans.org', u'90520CFDE846E7651A1B751FBC9BF8456E1C820B'),
    u'durand-gasselin': (u'adg@crans.org', u'B3EA34ED8A4EA3B5C3E6C04D30F01C448E96ACDA'),
    u'glondu': (u'Stephane.Glondu@crans.org', u'58EB0999C64E897EE894B8037853DA4D49881AD3'),
    u'huber': (u'olivier.huber@crans.org', u'3E9473AF796C530F9C4DE7DB1EF81A95E0DCF376'),
    u'iffrig': (u'iffrig@crans.org', u'26A210E2584208FEF6BE8F3718068DEA354B0045'),
    u'lagorce': (u'xavier.lagorce@crans.org', u'08C26F5AABC5570E5E2F52B39D9D7CE70BF3708E'),
    u'lajus': (u'lajus@crans.org', None),
    u'legallic': (u'legallic@crans.org', u'4BDD2DC3F10C26B9BC3B0BD93602E1C9A94025B0'),
    u'lerisson': (u'lerisson@crans.org', None),
    u'maioli': (u'maioli@crans.org', None),
    u'parret-freaud': (u'parret-freaud@crans.org', u'A93D3EB37C3669F89C01F9AE13AC8F777D980513'),
    u'samir': (u'samir@crans.org', u'C7B8823E96E8DC2798970340C86AD2AA41C2B76B'),
    u'tvincent': (u'vincent.thomas@crans.org', u'DFB04CE4394B1115C587AE101C6BE33AC5C4ACC0'),
#Autogen
    u'besson': (u'lbesson@ens-cachan.fr', None),#u'BF105A8DC75491B9D6EDAC5D01AACDB9C108F8A0',
    u'tilquin': (u'tilquin@crans.org', None),
    u'pvincent': (u'pvincent@crans.org', None),
    u'pommeret': (u'pommeret@crans.org', u'8D9C890BD2B783A052DBE71405504FF0CF875FE1'),
    u'lasseri': (u'lasseri@crans.org', u'31EF775095485A1CA4CC7CAAA2A902AE80403321'),
    u'moisy-mabille': (u'moisy-mabille@crans.org', None),
    u'guiraud': (u'guiraud@crans.org', u'8C8F34952DCBA75CD2963A4C33ECE62B57DA1CD4'),
    u'soret': (u'soret@crans.org', u'C244290074A0A4A8C05FCA1ACF25D25F17DA8589'),
    u'serrano': (u'serrano@crans.org', u'64ABC0C087EDAA14B79F5F7DEDE22762F030FDC5'),
    u'kherouf': (u'kherouf@crans.org', None),
    u'baste': (u'baste@crans.org', None),
    u'quelennec': (u'quelennec@crans.org', None),
    u'grande': (u'grande@crans.org', None),
    u'gstalter': (u'gstalter@crans.org', None),
    u'duplouy': (u'duplouy@crans.org', None),
    u'randazzo': (u'randazzo@crans.org', None),
    u'epalle': (u'epalle@crans.org', None),
    u'bonaque': (u'bonaque@crans.org', None),
    u'kviard': (u'kviard@crans.org', None)
}

#: Les variables suivantes sont utilisées pour définir le dictionnaire des
#: rôles.
RTC = [
    u'samir'
    ]

#: Liste des usernames des nounous
NOUNOUS = RTC + [
    u'blockelet',
    u'becue',
    u'dstan',
    u'chambart',
    u'dimino',
    u'durand-gasselin',
    u'glondu',
    u'huber',
    u'lagorce',
    u'parret-freaud',
    u'cauderlier',
    u'maioli',
    u'iffrig',
    u'boilard',
    u'legallic',
    u'pommeret',
    u'serrano',
    u'lasseri',
    ]

# Autogen:
#: Liste des usernames des apprentis
APPRENTIS = [
    u'grande',
    u'bonaque',
    u'moisy-mabille',
    u'baste',
    u'duplouy',
    u'besson',
    u'pvincent',
    u'quelennec',
    u'guiraud',
    u'kherouf',
    u'randazzo',
    u'tilquin',
    u'epalle',
    u'soret',
    u'gstalter',
    u'kviard']

#: Liste des usernames des membres du CA
CA = [
    u'becue',
    u'duplouy',
    u'epalle',
    u'guiraud',
    u'lajus',
    u'lasseri',
    u'lerisson',
    u'randazzo',
    u'soret',
    ]

#: Liste des trésoriers
TRESORERIE = RTC + [
    u'soret',
    u'guiraud',
    u'randazzo',
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
