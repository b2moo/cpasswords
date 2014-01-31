#!/bin/bash /usr/scripts/python.sh
# -*- coding: utf-8 -*-

from __future__ import print_function

from lc_ldap import shortcuts
import collections
import serverconfig_example as prev_config

conn = shortcuts.lc_ldap_admin()

role_of_droit = {
    u'apprenti': [u'apprentis',],
    u'bureau': [u'ca', u'ca-w',],
    u'tresorier': [u'tresorerie', u'tresorerie-w', ],
    u'nounou': [u'nounous', u'nounous-w', u'apprentis', u'apprentis-w'],
}

role_of_mail = {
    u'rtc@crans.org': [u'tresorerie', u'tresorerie-w', ],
    u'president@crans.org': [u'tresorerie', u'tresorerie-w', ],
}

def format_fpr(fpr):
    return fpr.replace(' ','')

def populate_db(login, field, value):
    print(("%s has no %s ldap value, populate ldap from former config " +
           "(value=%s) ? [yn]") % (login, field, value))
    if raw_input().lower() in ['y', 'o']:
        member = conn.search(u'uid=%s' % login, mode='rw')[0]
        member[field] = value
        member.history_add(unicode(shortcuts.current_user), unicode(field))
        member.save()
    else:
        print("Nevermind.")

roles = collections.defaultdict(list)
keys = dict()

fa = u'(|%s)' % u''.join(u'(droits=%s)' % x for x in role_of_droit.iterkeys())
fb = u'(|%s)' % u''.join(u'(mailAlias=%s)' % x for x in role_of_mail.iterkeys())

filterstr = u'(|%s%s)' % (fa, fb)

for member in conn.search(filterstr):
    login = member['uid'][0].value

    # On remplit la clé
    if member['gpgFingerprint']:
        fpr = format_fpr(member['gpgFingerprint'][0].value)
    elif prev_config.KEYS.get(login, (None,None))[1] is not None:
        fpr = prev_config.KEYS[login][1]
        populate_db(login, 'gpgFingerprint', fpr)
    else:
        fpr = None

    # Now le mail associé
    if member['gpgMail']:
        mail = member['gpgMail'][0].value
    elif fpr is not None and prev_config.KEYS.has_key(login):
        mail = prev_config.KEYS[login][0] # <!>
        populate_db(login, 'gpgMail', mail)
    else:
        #mail = login + u'@crans.org'
        # pas de fpr ni de mail, go away
        continue

    keys[login] = (mail, fpr)

    # Tous les droits pour login (sans doublon)
    his_roles = set()
    for droit in member['droits']:
        his_roles.update(role_of_droit.get(droit.value.lower(), []))

    for x in member['mailAlias']:
        his_roles.update(role_of_mail.get(x.value.lower(), []))
    
    # On remplit roles
    for role in his_roles:
        roles[role].append(login)

class NewConfig(object):
    KEYS = None
    ROLES = None
    def __init__(self, a, b):
        self.KEYS = a
        self.ROLES = b
    

new_config = NewConfig(keys, roles)
from diff_rights import diff_config
print(diff_config(prev_config, new_config))

