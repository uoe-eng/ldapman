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
import inspect


class LDAPSession(object):

    def __init__(self, conf):
        self._conn = None
        self.conf = conf

    def open(self):
        self.schema = None
        self.server = self.conf.globalconf.get('global', 'server')
        self._conn = ldap.initialize(self.server)
        sasl = ldap.sasl.gssapi()
        self._conn.sasl_interactive_bind_s('', sasl)

    def close(self):
        if self._conn is not None:
            self._conn.unbind_s()
            self._conn = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Any thrown exceptions in the context-managed region are ignored.
        # FIXME: Implement rollback if an exception is raised.
        self.close()
        return False  # we do not handle exceptions.

    def __enter__(self):
        self.open()
        return self

    def ldap_check_schema(self, objtype):

        if self.schema is None:
            subschemasubentry_dn, self.schema = ldap.schema.urlfetch(
                self.server)

        must = []
        may = []
        for entry in self.conf[objtype]['objectclass']:
            attrs = self.schema.get_obj(ldap.schema.ObjectClass, entry)
            must.extend(attrs.must)
            may.extend(attrs.may)
        return must, may

    def ldap_search(self, objtype, token,
                    scope=ldap.SCOPE_SUBTREE, timeout=-1):

        try:
            timeout = self.conf.globalconf.getfloat('global', 'timeout')
        except ConfigParser.Error:
            pass
        try:
            result = self._conn.search_st(self.conf[objtype]['base'],
                                          scope,
                                          filterstr=self.conf[objtype]['filter'] % (token) + "*",
                                          timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        # Result is a list of tuples, first item of which is DN
        # Strip off the base, then parition on = and keep value
        # Could alternatively split on = and keep first value?
        return [x[0].replace(
            ',' + self.conf[objtype]['base'], '').partition('=')[2] for x in result]

    def ldap_attrs(self, objtype, token,
                   scope=ldap.SCOPE_SUBTREE, timeout=-1):

        try:
            timeout = self.conf.globalconf.getfloat('global', 'timeout')
        except ConfigParser.Error:
            pass
        try:
            result = self._conn.search_st(self.conf[objtype]['base'],
                                          scope,
                                          filterstr=self.conf[objtype]['filter'] % (token),
                                          timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        return pprint.pformat(result)

    def ldap_add(self, objtype, args):

        attrs = {}
        cmdopts = ConfigParser.SafeConfigParser()
        # Preserve case of keys
        cmdopts.optionxform = str
        # Add an 'opts' section header to allow ConfigParser to work
        args = "[opts]\n" + args.replace(' ', '\n')
        cmdopts.readfp(io.BytesIO(args))

        attrs = dict(cmdopts.items('opts'))

        # Set objectclass(es) from config file
        attrs['objectclass'] = self.conf[objtype]['objectclass']

        # Add in any default attrs defined in the config file
        if self.conf[objtype]['defaultattrs']:
            attrs.update(self.conf[objtype]['defaultattrs'])

        missing = set(self.conf[objtype]['must']).difference(attrs.keys())
        if missing:
            raise ldap.LDAPError(
                "Missing mandatory attribute(s): %s" % ','.join(missing))

        # Convert the attrs dict into ldif
        ldif = ldap.modlist.addModlist(attrs)

        try:
            self._conn.add_s(self.conf.buildDN(attrs[self.conf[objtype]['filter'].partition('=')[0]], objtype), ldif)
        # TESTING!
        except Exception as e:
            print(e)

    def ldap_delete(self, objtype, args):

        # Delete the entry
        self._conn.delete_s(self.conf.buildDN(args, objtype))

    def ldap_rename(self, objtype, args):

        name, newname = args.split(' ')

        # Rename the entry
        self._conn.rename_s(self.conf.buildDN(name, objtype),
                            self.conf[objtype]['filter'] % (newname))

    def ldap_mod_attr(self, objtype, modmethod, attr, args):

        """Expects args to be of form 'object, items type, item1, item2...'"""

        obj, itemtype, items = args.split(None, 2)

        self._conn.modify_s(self.conf.buildDN(obj, child=objtype),
                            [(getattr(ldap, "MOD_" + modmethod.upper()),
                              attr,
                              self.conf.buildDN(item, child=itemtype))
                                for item in items.split()])

    def ldap_replace_attr(self, objtype, args):

        """Expects args to be the object, the attr to modify, and the replacement value."""

        obj, attr, value = args.split()

        self._conn.modify_s(self.conf.buildDN(obj, child=objtype),
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


class LDAPConfig(dict):
    def __init__(self, config):
        self.globalconf = config
        for section in config.sections():
            if section != 'global':
                # Read in all config options
                self[section] = dict(config.items(section))

                # Some config opts need 'work' before use...

                # Convert objectclass to a list
                if 'objectclass' in self[section]:
                    self[section]['objectclass'] = self[section]['objectclass'].split(',')

                # 'safe' eval defaultattrs to extract the dict
                if 'defaultattrs' in self[section]:
                    self[section]['defaultattrs'] = literal_eval(
                        self[section]['defaultattrs'])

    def buildDN(self, obj, child=None):
        conf = self[child] if child is not None else self
        return "%s,%s" % (conf['filter'] % (obj),
                          conf['base'])


def objtype(objtype):
    def annotateObjType(cls):
        orig_init = None
        if hasattr(cls, '__init__'):
            orig_init = cls.__init__

        def __init__(self, *args, **kwargs):
            self.objtype = objtype
            if orig_init is not None:
                orig_init(self, *args, **kwargs)

        cls.__init__ = __init__
        return cls
    return annotateObjType


def main():

    options, args = parse_opts()
    config = parse_config(options)

    # Create the objconf dict
    objconf = LDAPConfig(config)
    with LDAPSession(objconf) as ld:

        # Get schema info
        for section in config.sections():
            if section != 'global':
                objconf[section]['must'], objconf[section]['may'] = ld.ldap_check_schema(section)

        def complete_add(objtype, token=""):
            return shellac.complete_list(
                objconf[objtype]['must'] + objconf[objtype]['may'], token)

        class LDAPListCommands(object):

            def __init__(self):
                domethods = [mthdname.partition('_')[2] for mthdname, data
                             in inspect.getmembers(
                                 self, predicate=inspect.ismethod)
                             if mthdname.startswith('do_')]

                for mthd in domethods:
                    if hasattr(self, 'complete_' + mthd):
                        getattr(self, 'do_' + mthd).__func__.completions = [getattr(self, 'complete_' + mthd)]
                    else:
                        getattr(self, 'do_' + mthd).__func__.completions = [self.complete_default]

            def complete_default(self, token=""):
                return ld.ldap_search(self.objtype, token)

            def do_add(self, args):
                try:
                    ld.ldap_add(self.objtype, args)
                    print("Success!")
                except ldap.LDAPError as e:
                    print(e)

            def complete_add(self, token=""):
                return shellac.complete_list(
                    objconf[self.objtype]['must'] + objconf[self.objtype]['may'], token)

            def help_add(self, args):
                conf = objconf[self.objtype]
                return "Must: %s\nMay: %s\n" % (
                    ','.join(conf['must']), ','.join(conf['may']))

            def do_delete(self, args):

                if not options.force:
                    # prompt for confirmation
                    if not raw_input(
                            "Are you sure? (y/n):").lower().startswith('y'):
                        return

                try:
                    ld.ldap_delete(self.objtype, args)
                    print("Success!")
                except ldap.LDAPError as e:
                    print(e)

            def help_delete(self, args):
                return "Delete an entry (DN)"

            def do_rename(self, args):
                try:
                    ld.ldap_rename(self.objtype, args)
                    print("Success!")
                except ldap.LDAPError as e:
                    print(e)

            def do_edit(self, args):
                try:
                    ld.ldap_replace_attr(self.objtype, args)
                    print("Success!")
                except (ldap.LDAPError, ValueError) as e:
                    print(e)

            def do_search(self, args):
                try:
                    print(ld.ldap_search(self.objtype, args))
                except shellac.CompletionError:
                    print("Search timed out.")

            def do_show(self, args):
                try:
                    print(ld.ldap_attrs(self.objtype, args))
                except shellac.CompletionError:
                    print("Search timed out.")

        class LDAPShell(shellac.Shellac, object):

            @objtype("user")
            class do_user(LDAPListCommands):
                pass

            @objtype("group")
            class do_group(LDAPListCommands):

                class do_member():

                    @shellac.completer(partial(ld.ldap_search, "group"))
                    def do_add(self, args):
                        try:
                            ld.ldap_mod_attr("group", "add", "member", args)
                            print("Success!")
                        except (ldap.LDAPError, ValueError) as e:
                            print(e)

                    @shellac.completer(partial(ld.ldap_search, "group"))
                    def do_delete(self, args):
                        try:
                            ld.ldap_mod_attr("group", "delete", "member", args)
                            print("Success!")
                        except (ldap.LDAPError, ValueError) as e:
                            print(e)

        if len(args) != 0:
            LDAPShell().onecmd(' '.join(args))
        else:
            LDAPShell().cmdloop()


if __name__ == "__main__":
    main()
