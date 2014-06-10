#!/usr/bin/python

import shellac
import ldap
import ldap.sasl
import ldap.schema
import ldap.modlist
import sys
import ConfigParser
from optparse import OptionParser
from functools import partial, wraps
import io
from ast import literal_eval
import inspect
import os
import tempfile
import subprocess
import fcntl
import ldif
from StringIO import StringIO


def printexceptions(func):
    """Decorate the given function so that in debugging mode all unhandled
    tracebacks are printed and re-raised.

    """

    @wraps(func)
    def new_func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            print(sys.exc_info()[0])
            raise
    return new_func


class LDAPSession(object):
    """Container object for connection to an LDAP server."""

    def __init__(self, conf):
        self.conn = None
        self.conf = conf
        self.schema = None
        self.server = None

    def open(self):
        """Make a connection to the LDAP server."""

        self.server = self.conf.globalconf.get('global', 'server')
        self.conn = ldap.initialize(self.server)
        sasl = ldap.sasl.gssapi()
        self.conn.sasl_interactive_bind_s('', sasl)

    def close(self):
        """Close the connection to the LDAP server, if one exists."""

        if self.conn is not None:
            self.conn.unbind_s()
            self.conn = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Any thrown exceptions in the context-managed region are ignored.
        # FIXME: Implement rollback if an exception is raised.
        self.close()
        return False  # we do not handle exceptions.

    def __enter__(self):
        self.open()
        return self

    def ldap_to_ldif(self, pyld):
        """Convert python-ldap list of tuples into ldif string"""

        tmpf = StringIO()
        ldw = ldif.LDIFWriter(tmpf, cols=99999)
        [ldw.unparse(*item) for item in pyld]

        return tmpf.getvalue()

    def ldif_to_ldap(self, ldiff):
        """Convert ldif string into python-ldap list of tuples"""

        tmpf = StringIO()
        tmpf.write(ldiff)
        tmpf.seek(0)
        ldr = ldif.LDIFRecordList(tmpf)
        ldr.parse()
        return ldr.all_records

    def ldap_check_schema(self, objtype):
        """Retrieve the schema from the server, returning (must, may) lists
        of required and optional attributes of the requested objectclass.

        """

        if self.schema is None:
            _, self.schema = ldap.schema.urlfetch(self.server)
        if self.schema is None:
            raise Exception("Could not fetch schema.")

        must = []
        may = []
        for entry in self.conf[objtype]['objectclass']:
            # attribute_types returns 2 tuples of all must and may attrs,
            # including recursion into inherited attributes
            # This always includes 'objectClass' so discard this
            attrs = self.schema.attribute_types([entry])
            must.extend([item.names[0] for item in attrs[0].values() if not item.names[0] == "objectClass"])
            may.extend([item.names[0] for item in attrs[1].values() if not item.names[0] == "objectClass"])
        return must, may

    def ldap_search(self, objtype, token):
        """Search the tree for a matching entry."""

        timeout = float(self.conf.globalconf.get('global', 'timeout', vars={'timeout': '-1'}))
        try:
            scope = getattr(ldap, self.conf[objtype]['scope'])
        except KeyError:
            scope = ldap.SCOPE_ONELEVEL
        try:
            result = self.conn.search_st(self.conf[objtype]['base'],
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

    def ldap_attrs(self, objtype, token):
        """Get the attributes of an object."""

        timeout = float(self.conf.globalconf.get('global', 'timeout', vars={'timeout': '-1'}))
        try:
            scope = getattr(ldap, self.conf[objtype]['scope'])
        except KeyError:
            scope = ldap.SCOPE_ONELEVEL

        try:
            return self.conn.search_st(self.conf[objtype]['base'],
                                       scope,
                                       filterstr=self.conf[objtype]['filter'] % (token),
                                       timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

    @printexceptions
    def ldap_add(self, objtype, args, rdn=""):
        """Add an entry. rdn is an optional prefix to the DN."""

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
        ldiff = ldap.modlist.addModlist(attrs)

        dn = self.conf.buildDN(
            attrs[self.conf[objtype]['filter'].partition('=')[0]],
            objtype, rdn=rdn)
        self.conn.add_s(dn, ldiff)

    def ldap_delete(self, objtype, args):
        """Delete an entry by name."""
        self.conn.delete_s(self.conf.buildDN(args, objtype))

    def ldap_rename(self, objtype, args):
        """Rename an object. args must be 'name newname'."""

        name, newname = args.split()

        self.conn.rename_s(self.conf.buildDN(name, objtype),
                           self.conf[objtype]['filter'] % (newname))

    def ldap_mod_attr(self, objtype, modmethod, attr, args):
        """Modify an attribute. args must be of the form

        'object itemtype item1 item2...'

        """

        obj, itemtype, items = args.split(None, 2)

        self.conn.modify_s(self.conf.buildDN(obj, child=objtype),
                           [(getattr(ldap, "MOD_" + modmethod.upper()),
                             attr,
                             self.conf.buildDN(item, child=itemtype))
                               for item in items.split()])

    def ldap_replace_attr(self, objtype, args):
        """Replace an object. args must be

        'object attr replacementvalue'

        """

        obj, attr, value = args.split()

        self.conn.modify_s(self.conf.buildDN(obj, child=objtype),
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
    # FIXME(mrichar1): Change to a better default
    config.read(options.config or 'ldapman.conf')
    return config


class LDAPConfig(dict):
    """Store the config data for an LDAPSession object.

    These data come from the config file, with some special processing for
    things which look like lists or dicts.

    Include a convenient method, buildDN, to create a DN given an object class,
    optional base DN from the config and optional RDN.

    """

    def __init__(self, config):
        super(LDAPConfig, self).__init__(self)
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

    def buildDN(self, obj, child=None, rdn=""):
        if len(rdn) != 0:
            rdn += ','
        conf = self[child] if child is not None else self
        return "%s,%s%s" % (conf['filter'] % (obj),
                            rdn,
                            conf['base'])


def shell_factory(ld, config, options, objconf):
    # Get schema info from the LDAP
    for section in config.sections():
        if section != 'global':
            objconf[section]['must'], objconf[section]['may'] = ld.ldap_check_schema(section)

    # Create a decorator for LDAPListCommands subclasses.
    def objtype(objtype):
        """Decorator to add an "objtype" attribute to a class."""

        def annotateObjType(cls):
            orig_init = getattr(cls, '__init__', None)

            def __init__(self, *args, **kwargs):
                if orig_init is not None:
                    orig_init(self, *args, **kwargs)
                self.objtype = objtype

            cls.__init__ = __init__
            return cls
        return annotateObjType

    class LDAPListCommands(object):
        """Abstract class for LDAP entries with a "list" interface."""

        def __init__(self):
            self.objtype = None
            domethods = [mthdname.partition('_')[2] for mthdname, _
                         in inspect.getmembers(
                             self, predicate=inspect.ismethod)
                         if mthdname.startswith('do_')]

            for mthd in domethods:
                getattr(self, 'do_' + mthd).__func__.completions = [
                    getattr(self, 'complete_' + mthd, self.complete_default)]

        def complete_default(self, token=""):
            return ld.ldap_search(self.objtype, token)

        @printexceptions
        def do_add(self, args):
            ld.ldap_add(self.objtype, args)

        def complete_add(self, token=""):
            return shellac.complete_list(
                objconf[self.objtype]['must'] + objconf[self.objtype]['may'], token)

        def help_add(self, args):
            conf = objconf[self.objtype]
            return """\
Add a new entry.

Attributes for this entry:
Must include: %s
May include : %s

Usage: %s add attr=x [attr=y...]""" % (','.join(conf['must']),
                                       ','.join(conf['may']),
                                       self.objtype)

        @printexceptions
        def do_delete(self, args):
            # prompt for confirmation
            if options.force or raw_input(
                    "Are you sure? (y/n):").lower().startswith('y'):
                ld.ldap_delete(self.objtype, args)

        def help_delete(self, args):
            return """\
Delete an entry.

Usage: %s delete entry""" % (self.objtype)

        @printexceptions
        def do_rename(self, args):
            ld.ldap_rename(self.objtype, args)

        def help_rename(self, args):
            return """\
Rename an entry.

Usage: %s rename entry newname""" % (self.objtype)

        @printexceptions
        def do_edit(self, args):
            ld.ldap_replace_attr(self.objtype, args)

        def help_edit(self, args):
            return """\
Change the value of an attribute of an entry.

Usage: %s edit entry attr val""" % (self.objtype)

        def do_search(self, args):
            try:
                print(ld.ldap_search(self.objtype, args))
            except shellac.CompletionError:
                print("Search timed out.")

        def help_search(self, args):
            return """\
Search for entries which start with a pattern.

Usage: %s search pattern""" % (self.objtype)

        def do_show(self, args):
            print(ld.ldap_to_ldif(self.show(args)))

        def show(self, args):
            try:
                return ld.ldap_attrs(self.objtype, args)
            except shellac.CompletionError:
                return "Search timed out."

        def help_show(self, args):
            return """\
Show the attributes of an entry.

Usage: %s show entry""" % (self.objtype)

        @printexceptions
        def do_editor(self, args):
            result = self.show(args or '*')
            oldentries = dict(result)
            # Parse python-ldap dict into ldif, write into a tempfile
            with tempfile.TemporaryFile() as tmpf:
                tmpf.write(ld.ldap_to_ldif(result))
                tmpf.seek(0, 0)
                fcntl.fcntl(tmpf.fileno(), fcntl.F_SETFD, 0)  # clear FD_CLOEXEC
                # Open the tempfile in an editor
                if subprocess.call([os.getenv('EDITOR', "/usr/bin/vi"),
                                    '/dev/fd/%d' % tmpf.fileno()]) != 0:
                    print("Editor exited non-zero, aborting.")
                    return

                # Parse the tempfile ldif back to a dict, then close tempfile
                tmpf.seek(0, 0)
                newentries = dict(ld.ldif_to_ldap(tmpf.read()))

            for dn, val in newentries.items():
                if dn not in oldentries:
                    ld.conn.add_s(dn,
                                  ldap.modlist.addModlist(val))
                elif oldentries[dn] != newentries[dn]:
                    ld.conn.modify_s(dn,
                                     ldap.modlist.modifyModlist(oldentries[dn], val))
            for dn in oldentries:
                if dn not in newentries:
                    ld.conn.delete_s(dn)

    class LDAPShell(shellac.Shellac, object):

        @objtype("user")
        class do_user(LDAPListCommands):
            pass

        @objtype("group")
        class do_group(LDAPListCommands):

            class do_member(object):

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "group"))
                @printexceptions
                def do_add(args):
                    ld.ldap_mod_attr("group", "add", "member", args)

                @staticmethod
                def help_add(args):
                    return """\
Add an entry to the member attribute for a group.

'type' can be any of the entry types for which a base DN is specified in the configuration.

Usage: group member add type entry
Example: group member add user josoap"""

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "group"))
                @printexceptions
                def do_delete(args):
                    ld.ldap_mod_attr("group", "delete", "member", args)

                @staticmethod
                def help_delete(args):
                    return """\
Delete an entry from the member attribute for a group.

'type' can be any of the entry types for which a base DN is specified in the configuration.

Usage: group member delete type entry
Example: group member delete user josoap"""

        @objtype("automount")
        class do_automount(LDAPListCommands):

            @objtype("automap")
            class do_map(LDAPListCommands):
                pass

            @shellac.completer(partial(ld.ldap_search, "automount"))
            @printexceptions
            def do_add(self, args):
                rdn = [x for x in args.split() if x.startswith('nisMapName')][0]
                ld.ldap_add(self.objtype, args, rdn=rdn)

        @objtype("dyngroup")
        class do_dyngroup(LDAPListCommands):
            pass

    return LDAPShell()


def main():
    options, args = parse_opts()
    config = parse_config(options)

    # Create the objconf dict
    objconf = LDAPConfig(config)

    # Bind the LDAP, so that our shell objects can access it
    with LDAPSession(objconf) as ld:

        shell = shell_factory(ld, config, options, objconf)
        if len(args) != 0:
            shell.onecmd(' '.join(args))
        else:
            shell.cmdloop()


if __name__ == "__main__":
    main()
