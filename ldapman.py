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
from ast import literal_eval


class LDAPSession(object):

    def __init__(self):
        self._conn = None
        self.closed = True

    def open(self):
        self.schema = None
        self.server = config.get('global', 'server')
        self._conn = ldap.initialize(self.server)
        sasl = ldap.sasl.gssapi()
        self._conn.sasl_interactive_bind_s('', sasl)
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

    def buildDN(self, objconf, obj):
        return "%s,%s" % (objconf['filter'] % (obj),
                          objconf['base'])

    def ldap_check_schema(self, objconf):

        if self.schema is None:
            subschemasubentry_dn, self.schema = ldap.schema.urlfetch(
                self.server)

        must = []
        may = []
        for entry in objconf['objectclass']:
            attrs = self.schema.get_obj(ldap.schema.ObjectClass, entry)
            must.extend(attrs.must)
            may.extend(attrs.may)
        return must, may

    def ldap_search(self, objconf, token,
                    scope=ldap.SCOPE_SUBTREE, timeout=-1):

        try:
            timeout = config.getfloat('global', 'timeout')
        except ConfigParser.Error:
            pass
        try:
            result = self._conn.search_st(objconf['base'],
                                          scope,
                                          filterstr=objconf['filter'] % (token) + "*",
                                          timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        # Result is a list of tuples, first item of which is DN
        # Strip off the base, then parition on = and keep value
        # Could alternatively split on = and keep first value?
        return [x[0].replace(
            ',' + objconf['base'], '').partition('=')[2] for x in result]

    def ldap_attrs(self, objconf, token,
                   scope=ldap.SCOPE_SUBTREE, timeout=-1):

        try:
            timeout = config.getfloat('global', 'timeout')
        except ConfigParser.Error:
            pass
        try:
            result = self._conn.search_st(objconf['base'],
                                          scope,
                                          filterstr=objconf['filter'] % (token) + "*",
                                          timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        return pprint.pformat(result)

    def ldap_add(self, objconf, args):

        attrs = {}
        cmdopts = ConfigParser.SafeConfigParser()
        # Preserve case of keys
        cmdopts.optionxform = str
        # Add an 'opts' section header to allow ConfigParser to work
        args = "[opts]\n" + args.replace(' ', '\n')
        cmdopts.readfp(io.BytesIO(args))

        attrs = dict(cmdopts.items('opts'))

        # Set objectclass(es) from config file
        attrs['objectclass'] = objconf['objectclass']

        # Add in any default attrs defined in the config file
        if objconf['defaultattrs']:
            attrs.update(objconf['defaultattrs'])

        missing = set(objconf['must']).difference(attrs.keys())
        if missing:
            raise ldap.LDAPError(
                "Missing mandatory attribute(s): %s" % ','.join(missing))

        # Convert the attrs dict into ldif
        ldif = ldap.modlist.addModlist(attrs)

        self._conn.add_s(self.buildDN(objconf,
                                      attrs[objconf['filter'].partition('=')[0]]), ldif)

    def ldap_delete(self, objconf, args):

        # Delete the entry
        self._conn.delete_s(self.buildDN(objconf, args))

    def ldap_rename(self, objconf, args):

        name, newname = args.split(' ')

        # Rename the entry
        self._conn.rename_s(self.buildDN(objconf, name),
                            objconf['filter'] % (newname))

    def ldap_mod_attr(self, objconf, objtype, modmethod, attr, args):

        """Expects args to be of form 'object, items type, item1, item2...'"""

        obj, itemtype, items = args.split(None, 2)

        self._conn.modify_s(self.buildDN(objconf[objtype], obj),
                            [(getattr(ldap, "MOD_" + modmethod.upper()),
                              attr,
                              self.buildDN(objconf[itemtype], item)) for item in items.split()])

    def ldap_replace_attr(self, objconf, objtype, args):

        """Expects args to be the object, the attr to modify, and the replacement value."""

        obj, attr, value = args.split()

        self._conn.modify_s(self.buildDN(objconf[objtype], obj),
                            [(ldap.MOD_REPLACE, attr, value)])


def parse_opts():
    """Handle command-line arguments"""

    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config",
                      help="Path to configuration file")

    parser.add_option("-f", "--force", dest="force",
                      action="store_true", default=False,
                      help="Don't prompt for confirmation for operations")

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

        def build_objconf():

            objconf = {}
            for section in config.sections():
                if section != 'global':
                    # Read in all config options
                    objconf[section] = dict(config.items(section))

                    # Some config opts need 'work' before use...

                    # Convert objectclass to a list
                    if 'objectclass' in objconf[section]:
                        objconf[section]['objectclass'] = objconf[section]['objectclass'].split(',')

                    # 'safe' eval defaultattrs to extract the dict
                    if 'defaultattrs' in objconf[section]:
                        objconf[section]['defaultattrs'] = literal_eval(
                            objconf[section]['defaultattrs'])

                    # Get schema info
                    objconf[section]['must'], objconf[section]['may'] = ld.ldap_check_schema(objconf[section])

            return objconf

        def complete_add(objconf, token=""):
            return shellac.complete_list(
                objconf['must'] + objconf['may'], token)

        # Create the objconf dict
        objconf = build_objconf()

        class LDAPShell(shellac.Shellac, object):

            class do_user():

                def do_add(self, args):
                    print("Method not implemented.")

                @shellac.completer(partial(ld.ldap_search, objconf["user"]))
                def do_edit(self, args):
                    print("Method not implemented.")

                @shellac.completer(partial(ld.ldap_search, objconf["user"]))
                def do_search(self, args):
                    try:
                        print(ld.ldap_attrs(objconf["user"], args))
                    except shellac.CompletionError:
                        print("Search timed out.")

            class do_group():

                @shellac.completer(partial(complete_add, objconf["group"]))
                def do_add(self, args):
                    try:
                        ld.ldap_add(objconf["group"], args)
                        print("Success!")
                    except ldap.LDAPError as e:
                        print(e)

                def help_add(self, args):
                    conf = objconf["group"]
                    return "Must: %s\nMay: %s\n" % (
                        ','.join(conf.must), ','.join(conf.may))

                @shellac.completer(partial(ld.ldap_search, objconf["group"]))
                def do_delete(self, args):

                    if not options.force:
                        # prompt for confirmation
                        if not raw_input(
                                "Are you sure? (y/n):").lower().startswith('y'):
                            return

                    try:
                        ld.ldap_delete(objconf["group"], args)
                        print("Success!")
                    except ldap.LDAPError as e:
                        print(e)

                def help_delete(self, args):
                    conf = objconf["group"]
                    return "Delete an entry (DN)"

                @shellac.completer(partial(ld.ldap_search, objconf["group"]))
                def do_addmember(self, args):
                    try:
                        ld.ldap_mod_attr(objconf, "group", "add", "member", args)
                        print("Success!")
                    except (ldap.LDAPError, ValueError) as e:
                        print(e)

                @shellac.completer(partial(ld.ldap_search, objconf["group"]))
                def do_delmember(self, args):
                    try:
                        ld.ldap_mod_attr(objconf, "group", "delete", "member", args)
                        print("Success!")
                    except (ldap.LDAPError, ValueError) as e:
                        print(e)

                @shellac.completer(partial(ld.ldap_search, objconf["group"]))
                def do_rename(self, args):
                    try:
                        ld.ldap_rename(objconf["group"], args)
                        print("Success!")
                    except ldap.LDAPError as e:
                        print(e)

                @shellac.completer(partial(ld.ldap_search, objconf["group"]))
                def do_edit(self, args):
                    try:
                        ld.ldap_replace_attr(objconf, "group", args)
                        print("Success!")
                    except (ldap.LDAPError, ValueError) as e:
                        print(e)

                @shellac.completer(partial(ld.ldap_search, objconf["group"]))
                def do_search(self, args):
                    print(ld.ldap_attrs(objconf["group"], args))

        if len(args) != 0:
            LDAPShell().onecmd(' '.join(args))
        else:
            LDAPShell().cmdloop()


options, args = parse_opts()
config = parse_config(options)


if __name__ == "__main__":
    main()
