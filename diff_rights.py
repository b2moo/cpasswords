#!/usr/bin/env python
# -*- coding: utf-8 -*-

def _setify_roles(roles):
    """Makes set of pairs (rolename, user)"""
    out = set()
    role_names = roles.keys()
    list.sort(role_names)
    
    for k in role_names:
        list.sort(roles[k])
        for v in roles[k]:
            out.add((k,v))
    return out

def diff_set(a, b, item_dump):
    """Return difference between two sets"""
    out = u""
    added = set()
    deleted = set()
    for x in a.symmetric_difference(b):
        if x in b:
            added.add(x)
        else:
            deleted.add(x)
    out += u" * Added *\n"
    for x in added:
        out += u"  " + item_dump(x) + u'\n'
    out += u" * Removed *\n"
    for x in deleted:
        out += u"  " + item_dump(x) + u'\n'
    return out

def _dump_key_pair(item):
    if item[1][1] is not None:
        return "%s with key %s (%s)" % (item[0], item[1][0], item[1][1])
    else:
        return "%s with mail %s (no key)" % (item[0], item[1][0])

def _dump_role_pair(item):
    return "%s in %s" % (item[1], item[0])

def diff_config(cfga, cfgb):
    """Compare two server configurations"""
    out = u"** Keys **\n"
    out += diff_set(set(cfga.KEYS.items()), set(cfgb.KEYS.items()), _dump_key_pair)
    out += u"** Roles **\n"
    out += diff_set(_setify_roles(cfga.ROLES),
                    _setify_roles(cfgb.ROLES), _dump_role_pair)
    return out

# test
if __name__ == '__main__':
    import serverconfig2
    import serverconfig
    print diff_config(serverconfig, serverconfig2)

