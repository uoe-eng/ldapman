#!/usr/bin/python

"""LDAPMan: a command-line shell for managing LDAP objects."""

from __future__ import print_function

from . import errors, ldapsession, util

import ConfigParser
import atexit
import fcntl
from functools import partial
import inspect
import ldap
import ldap.modlist
import os
import shellac
import subprocess
import tempfile


def shell_factory(ld, config, options, objconf):
    # Get schema info from the LDAP
    for section in config.sections():
        if section != 'global':
            objconf[section]['must'], objconf[section]['may'] = ld.ldap_check_schema(section)

    # Create a decorator for LDAPListCommands subclasses.
    def objtype(objtype):
        """Decorator to add an "objtype" attribute to a class."""

        def annotate_obj_type(cls):
            orig_init = getattr(cls, '__init__', None)

            def __init__(self, *args, **kwargs):
                if orig_init is not None:
                    orig_init(self, *args, **kwargs)
                self.objtype = objtype

            cls.__init__ = __init__
            return cls
        return annotate_obj_type

    def safe_to_continue():
        """Returns true if force set, or interactive and 'y' pressed."""
        if options.force or (options.interactive and raw_input(
                "Are you sure? (y/n):").lower().startswith('y')):
            return True

    def safety_check(func):
        """A decorator to abort "unsafe" operations without explicit permission."""

        def new_func(*args, **kwargs):
            if safe_to_continue():
                return func(*args, **kwargs)
        return new_func

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
            """Default completion method if no explicit method set."""
            return ld.ldap_search(self.objtype, token)

        @util.printexceptions
        def do_add(self, args):
            """Add an LDAP object."""
            ld.ldap_add(self.objtype, args)

        def complete_add(self, token=""):
            """Completion method for do_add."""
            return shellac.complete_list(
                objconf[self.objtype]['must'] + objconf[self.objtype]['may'], token)

        def help_add(self, args):
            """help method for do_add."""
            conf = objconf[self.objtype]
            return """\
Add a new entry.

Attributes for this entry:
Must include: %s
May include : %s

Usage: %s add attr=x [attr=y...]""" % (','.join(conf['must']),
                                       ','.join(conf['may']),
                                       self.objtype)

        @util.printexceptions
        @safety_check
        def do_delete(self, args):
            """Delete an LDAP object."""
            ld.ldap_delete(self.objtype, args)

        def help_delete(self, args):
            """help method for do_delete."""
            return """\
Delete an entry.

Usage: %s delete entry""" % (self.objtype)

        @util.printexceptions
        def do_rename(self, args):
            """Rename an LDAP object."""
            try:
                ld.ldap_rename(self.objtype, args)
            except ValueError:
                print("Wrong number of arguments supplied. See help for more information.")

        def help_rename(self, args):
            """help method for do_rename."""
            return """\
Rename an entry.

Usage: %s rename entry newname""" % (self.objtype)

        @util.printexceptions
        def do_modify(self, args):
            """Modify the attributes of an LDAP object."""
            try:
                obj, attr, value = args.split()
                ld.ldap_replace_attr(self.objtype, obj, attr, value)
            except ValueError:
                print("Wrong number of arguments supplied. See help for more information.")

        def help_modify(self, args):
            """help method for do_modify."""
            return """\
Change the value of an attribute of an entry.

Usage: %s modify entry attr val""" % (self.objtype)

        def do_search(self, args):
            """Search for LDAP objects."""
            try:
                print(ld.ldap_search(self.objtype, args))
            except shellac.CompletionError:
                print("Search timed out.")

        def help_search(self, args):
            """help method for do_search."""
            return """\
Search for entries which start with a pattern.

Usage: %s search pattern""" % (self.objtype)

        def do_show(self, args):
            """Show the attributes of an LDAP object."""
            print(ld.ldap_to_ldif(self.show(args)))

        def show(self, args):
            """Gets an object's attributes for do_show method."""
            try:
                return ld.ldap_attrs(self.objtype, args)
            except shellac.CompletionError:
                return "Search timed out."

        def help_show(self, args):
            """help method for do_show."""
            return """\
Show the attributes of an entry.

Usage: %s show entry""" % (self.objtype)

        @util.printexceptions
        def do_edit(self, args):
            """Edit the ldif of an LDAP object with $EDITOR."""
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

            adds, mods, dels = util.compare_dicts(oldentries, newentries)

            print("Changes: %d Addition(s), %d Modification(s), %d Deletion(s)." %
                  (len(adds.keys()), len(mods.keys()), len(dels.keys())))

            if safe_to_continue():
                for dn, val in adds.items():
                    ld.conn.add_s(dn, ldap.modlist.addModlist(val))
                for dn, (oldval, newval) in mods.items():
                    ld.conn.modify_s(dn,
                                     ldap.modlist.modifyModlist(oldval, newval))
                for dn in dels.keys():
                    ld.conn.delete_s(dn)
            else:
                print("No changes made.")

        def help_edit(self, args):
            """help method for do_edit."""
            return """\
Open the object(s) in a text editor for editing.
($EDITOR = %s)

Usage: %s edit entry""" % (os.getenv("EDITOR", "/usr/bin/vi"), self.objtype)

    class LDAPMan(shellac.Shellac, object):
        """
LDAPman shell environment
-------------------------

Press TAB to see possible completions.
        """

        @objtype("user")
        class do_user(LDAPListCommands):
            """Add a placeholder for a user menu item."""
            pass

        @objtype("group")
        class do_group(LDAPListCommands):
            """Add a group menu item."""

            class do_member(object):
                """Add a member menu item."""

                def __init__(self):
                    self.do_add.completions = [self.complete_add]
                    self.do_delete.completions = [self.complete_delete]

                @staticmethod
                def complete_add(token=""):
                    """complete method for do_add."""
                    endidx = shellac.readline.get_endidx()
                    buf = shellac.readline.get_line_buffer()
                    if len(buf[:endidx].split(' ', -1)) >= 5:
                        return ld.ldap_search("user", token)
                    else:
                        return ld.ldap_search("group", token)

                @staticmethod
                @util.printexceptions
                def do_add(args):
                    """add method for group member."""
                    try:
                        group, members = args.split(None, 2)

                        ld.ldap_mod_attr("group", "add", "member", group,
                                         [objconf.build_dn(member, child="user") for member in members.split()])
                    except ValueError:
                        print("Wrong number of arguments supplied. See help for more information.")

                @staticmethod
                def help_add(args):
                    """help method for do_add."""
                    return """\
Add an entry to the member attribute for a group.

Usage: group member add <group> <member>
Example: group member add staff josoap"""

                @staticmethod
                def complete_delete(token=""):
                    """complete method for do_delete."""
                    endidx = shellac.readline.get_endidx()
                    buf = shellac.readline.get_line_buffer()
                    if len(buf[:endidx].split(' ', -1)) >= 5:
                        # Return usernames from the group set to be deleted
                        # ldap_attrs returns a list of tuples (DN, attrs dict)
                        return shellac.complete_list(
                            [util.get_rdn(x) for
                             x in ld.ldap_attrs("group",
                                                buf.split(' ', -1)[3]
                                               )[0][1]['member']], token)
                    else:
                        return ld.ldap_search("group", token)

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "group"))
                @util.printexceptions
                @safety_check
                def do_delete(args):
                    """delete method for group member."""
                    try:
                        group, members = args.split(None, 2)

                        ld.ldap_mod_attr("group", "delete", "member", group,
                                         [objconf.build_dn(member, child="user") for member in members.split()])
                    except ValueError:
                        print("Wrong number of arguments supplied. See help for more information.")

                @staticmethod
                def help_delete(args):
                    """help method for do_delete."""
                    return """\
Delete an entry from the member attribute for a group.

Usage: group member delete <group> <member>
Example: group member delete staff josoap"""

        @objtype("netgroup")
        class do_netgroup(LDAPListCommands):
            """Add a netgroup menu item."""

            class do_member(object):
                """Add a member menu item."""

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "netgroup"))
                @util.printexceptions
                def do_add(args):
                    """add method for netgroup member."""
                    try:
                        netgroup, members = args.split(None, 2)
                        ld.ldap_mod_attr("netgroup", "add",
                                         "memberNisNetgroup", netgroup,
                                         members.split())
                    except ValueError:
                        print("Wrong number of arguments supplied. See help for more information.")

                @staticmethod
                def help_add(args):
                    """help method for do_add."""
                    return """\
Add a new netgroup member for a netgroup.

Usage: netgroup member add <group> <member>
Example: netgroup member add students year1"""

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "netgroup"))
                @util.printexceptions
                @safety_check
                def do_delete(args):
                    """delete method for netgroup member."""
                    try:
                        netgroup, members = args.split(None, 2)
                        ld.ldap_mod_attr("netgroup", "delete",
                                         "memberNisNetgroup", netgroup,
                                         members.split())
                    except ValueError:
                        print ("Wrong number of arguments supplied. See help for more information.")

                @staticmethod
                def help_delete(args):
                    """help method for do_delete."""
                    return """\
Delete a netgroup member attribute for a netgroup.

Usage: netgroup member delete <group> <member>
Example: netgroup member delete students year1"""

            class do_triple(object):
                """Add a triple menu item."""

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "netgroup"))
                @util.printexceptions
                def do_add(args):
                    """add method for netgroup triple."""
                    try:
                        netgroup, triples = args.split(None, 2)
                        ld.ldap_mod_attr("netgroup", "add",
                                         "nisNetgroupTriple", netgroup,
                                         triples.split())
                    except ValueError:
                        print("Wrong number of arguments supplied. See help for more information.")

                @staticmethod
                def help_add(args):
                    """help method for do_add."""
                    return """\
Add a new netgroup triple to a netgroup.

Usage: netgroup triple add <groupname> <triple>
Example: netgroup triple add staff (,josoap,)"""

                @staticmethod
                @shellac.completer(partial(ld.ldap_search, "netgroup"))
                @util.printexceptions
                @safety_check
                def do_delete(args):
                    """delete method for netgroup member."""
                    try:
                        netgroup, triples = args.split(None, 2)
                        ld.ldap_mod_attr("netgroup", "delete",
                                         "nisNetgroupTriple", netgroup,
                                         triples.split())
                    except ValueError:
                        print("Wrong number of arguments supplied. See help for more information.")

                @staticmethod
                def help_delete(args):
                    """help method for do_delete."""
                    return """\
Delete a netgroup triple from a netgroup.

Usage: netgroup triple delete <groupname> <triple>
Example: netgroup member delete ng1 (,josoap,)"""

        @objtype("automount")
        class do_automount(LDAPListCommands):
            """Add automount menu item."""

            @objtype("automap")
            class do_map(LDAPListCommands):
                """Placeholder for automount maps menu."""
                pass

            @shellac.completer(partial(ld.ldap_search, "automount"))
            @util.printexceptions
            def do_add(self, args):
                """add method for automount."""
                rdn = [x for x in args.split() if x.startswith('nisMapName')][0]
                ld.ldap_add(self.objtype, args, rdn=rdn)

        @objtype("dyngroup")
        class do_dyngroup(LDAPListCommands):
            """Placeholder for dynamic groups menu."""
            pass

    return LDAPMan()


def main():
    """Start here."""
    options, args = util.parse_opts()
    config = util.parse_config(options)

    options.interactive = len(args) == 0

    # Try to read the ldapman history file
    hist_file = os.environ['HOME'] + '/.ldapman_history'
    try:
        shellac.readline.read_history_file(hist_file)
        atexit.register(shellac.readline.write_history_file, hist_file)
    except (KeyError, IOError):
        pass

    # Create the objconf dict
    objconf = util.LDAPConfig(config)

    # Bind the LDAP, so that our shell objects can access it
    with ldapsession.LDAPSession(objconf) as ld:

        shell = shell_factory(ld, config, options, objconf)
        if options.interactive:
            shell.cmdloop()
        else:
            shell.onecmd(' '.join(args))

