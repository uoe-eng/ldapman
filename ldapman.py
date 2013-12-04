#!/usr/bin/python

import shellac
import ldap
import ldap.sasl
import ldap.schema
import ldap.modlist
import sys
import pprint
import ConfigParser
from optparse import OptionParser
from contextlib import closing
from functools import partial
import io


class LDAPSession(object):

    def __init__(self):
        self._conn = None
        self.closed = True

    def open(self):
        server = config.get('global', 'server')
        self._conn = ldap.initialize(server)
        sasl = ldap.sasl.gssapi()
        self._conn.sasl_interactive_bind_s('', sasl)
        subschemasubentry_dn, self.schema = ldap.schema.urlfetch(server)
        self.closed = False

    def close(self):
        if not self.closed:
            self._conn.unbind_s()
            self.closed = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Any thrown exceptions in the context-managed region are ignored.
        # FIXME: Implement rollback if an exception is raised.
        self.close()
        return False  # we do not handle exceptions.

    def __enter__(self):
        self.open()
        return self

    def ldap_objc(self, searchtype, token=""):
        must = []
        may = []
        for objc in config.get(searchtype, 'objectclass').split(','):
            attrs = self.schema.get_obj(ldap.schema.ObjectClass, objc)
            must.extend(attrs.must)
            may.extend(attrs.may)
        return must, may

    def ldap_search(self, searchtype, token,
                    scope=ldap.SCOPE_SUBTREE, timeout=-1):

        base = config.get(searchtype, 'base')
        filterstr = config.get(searchtype, 'filter')

        try:
            timeout = config.getfloat('global', 'timeout')
        except ConfigParser.Error:
            pass
        try:
            result = self._conn.search_st(base,
                                          scope,
                                          filterstr=filterstr % (token),
                                          timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        # Result is a list of tuples, first item of which is DN
        # Strip off the base, then parition on = and keep value
        # Could alternatively split on = and keep first value?
        return [x[0].replace(',' + base, '').partition('=')[2] for x in result]

    def ldap_attrs(self, searchtype, token,
                   scope=ldap.SCOPE_SUBTREE, timeout=-1):

        base = config.get(searchtype, 'base')
        filterstr = config.get(searchtype, 'filter')

        try:
            timeout = config.getfloat('global', 'timeout')
        except ConfigParser.Error:
            pass
        try:
            result = self._conn.search_st(base,
                                          scope,
                                          filterstr=filterstr % (token),
                                          timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        return pprint.pformat(result)

    def ldap_add(self, searchtype, args):

        attrs = {}
        cmdopts = ConfigParser.SafeConfigParser()
        # Preserve case of keys
        cmdopts.optionxform = str
        # Add an 'opts' section header to allow ConfigParser to work
        args = "[opts]\n" + args.replace(' ', '\n')
        cmdopts.readfp(io.BytesIO(args))

        attrs = dict(cmdopts.items('opts'))

        # FIXME: group-specific config
        # set an empty members list by default
        attrs['member'] = ['']
        attrs['objectclass'] = config.get(searchtype, 'objectclass').split(',')

        # Check that all 'must' attrs are provided
        must, may = self.ldap_objc(searchtype)

        missing = set(must).difference(attrs.keys())
        if len(missing):
            raise ldap.LDAPError(
                "Missing mandatory attribute(s): %s" % ','.join(missing))

        dn = "cn=%s,%s" % (attrs['cn'], config.get(searchtype, 'base'))

        # Convert the attrs dict into ldif
        ldif = ldap.modlist.addModlist(attrs)

        self._conn.add_s(dn, ldif)


def parse_opts():
    """Handle command-line arguments"""

    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config",
                      help="Path to configuration file")

    return parser.parse_args()


def parse_config(options):
    """Read in a config file"""

    config = ConfigParser.SafeConfigParser()
    # FIX: Change to a better default
    config_file = 'ldapman.conf'
    if options.config:
        config_file = options.config
    config.read(config_file)

    return config


def main():
    with LDAPSession() as ld:

        def complete_add(searchtype, token=""):
            must, may = ld.ldap_objc(searchtype)
            return shellac.complete_list(must + may, token)

        class LDAPShell(shellac.Shellac, object):

            class do_user():

                def do_add(self, args):
                    print("Added user: ", args)

                @shellac.completer(partial(ld.ldap_search, "user"))
                def do_edit(self, args):
                    print("Edited user: ", args)

                @shellac.completer(partial(ld.ldap_search, "user"))
                def do_search(self, args):
                    print(ld.ldap_attrs("user", args))

            class do_group():

                @shellac.completer(partial(complete_add, "group"))
                def do_add(self, args):
                    try:
                        ld.ldap_add("group", args)
                        print("Success!")
                    except ldap.LDAPError as e:
                        print(e)

                def help_add(self, args):
                    must, may = ld.ldap_objc("group")
                    return "Must: %s\nMay: %s\n" % (','.join(must), ','.join(may))

                @shellac.completer(partial(ld.ldap_search, "group"))
                def do_edit(self, args):
                    print("Edited group: ", args)

                @shellac.completer(partial(ld.ldap_search, "group"))
                def do_search(self, args):
                    print(ld.ldap_attrs("group", args))

        if len(args) != 0:
            LDAPShell().onecmd(' '.join(args))
        else:
            LDAPShell().cmdloop()


options, args = parse_opts()
config = parse_config(options)


if __name__ == "__main__":
    main()
