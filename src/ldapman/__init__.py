"""LDAPMan: a command-line shell for managing LDAP objects."""

from __future__ import print_function

from . import errors, ldapsession, util

import ConfigParser
import atexit
import fcntl
from functools import partial
import inspect
import ldap.modlist
import os
import shellac
import subprocess
import sys
import tempfile


def shell_factory(ldconn, config, options, objconf):
    """Factory to generate ldapman shells."""

    # Get schema info from the LDAP
    for section in config.sections():
        if section != 'global':
            objconf[section]['must'], objconf[section]['may'] = ldconn.ldap_check_schema(section)

    # Create a decorator for LDAPListCommands subclasses.
    def objtype(objtype):
        """Decorator to add an "objtype" attribute to a class."""

        def annotate_obj_type(cls):
            """function returned by the decorator."""

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
            """function returned by the decorator."""

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

        def complete_default(self, token="", objtype=None):
            """Default completion method if no explicit method set."""

            # ldap_search returns a generator containing a list,
            # where each item is a list containing a tuple.
            # the tuple contains the DN, and the object attributes
            # Use get_rdn to extract just the value of the first RDN
            if not objtype:
                objtype = self.objtype

            try:
                return [util.get_rdn(x[0][0]) for x in ldconn.ldap_search(objtype, token)]
            except KeyboardInterrupt:
                shellac.Shellac().cancel(prompt=True)

        @util.printexceptions
        def do_add(self, args):
            """Add an LDAP object."""
            ldconn.ldap_add(self.objtype, args)

        def complete_add(self, token=""):
            """Completion method for do_add."""
            return shellac.complete_list(
                objconf[self.objtype]['must'] + objconf[self.objtype]['may'], token, append_character="=")

        def help_add(self, args):
            """help method for do_add."""
            conf = objconf[self.objtype]
            return """\
Add a new entry.

Attributes for this entry:
Must include: {0}
May include : {1}

Usage: {2} add attr=x [attr=y...]""".format(','.join(conf['must']),
                                            ','.join(conf['may']),
                                            self.objtype)

        @util.printexceptions
        @safety_check
        def do_delete(self, args):
            """Delete an LDAP object."""
            ldconn.ldap_delete(self.objtype, args)

        def help_delete(self, args):
            """help method for do_delete."""
            return """\
Delete an entry.

Usage: {0} delete entry""".format(self.objtype)

        @util.printexceptions
        def do_rename(self, args):
            """Rename an LDAP object."""
            try:
                ldconn.ldap_rename(self.objtype, args)
            except ValueError:
                print("Wrong number of arguments supplied. See help for more information.")

        def help_rename(self, args):
            """help method for do_rename."""
            return """\
Rename an entry.

Usage: {0} rename entry newname""".format(self.objtype)

        @util.printexceptions
        def do_modify(self, args):
            """Modify the attributes of an LDAP object."""
            try:
                obj, attr, value = args.split()
                ldconn.ldap_replace_attr(self.objtype, obj, attr, value)
            except ValueError:
                print("Wrong number of arguments supplied. See help for more information.")

        def help_modify(self, args):
            """help method for do_modify."""
            return """\
Change the value of an attribute of an entry.

Usage: {0} modify entry attr val""".format(self.objtype)

        def do_search(self, args):
            """Search for LDAP objects."""

            for rdata in ldconn.ldap_search(self.objtype, args):
                print(util.get_rdn(rdata[0][0]))

        def help_search(self, args):
            """help method for do_search."""
            return """\
Search for entries which start with a pattern.

Usage: {0} search pattern""".format(self.objtype)

        @util.printexceptions
        def do_show(self, args):
            """Show the attributes of a list of LDAP objects."""

            for rdata in self.get_attrs(args):
                print(ldconn.ldap_to_ldif(rdata))

        @util.printexceptions
        def get_attrs(self, args):
            """Retrieve the attributes of a list of LDAP objects."""

            for arg in args.split():
                for rdata in ldconn.ldap_attrs(self.objtype, arg):
                    yield rdata

        def help_show(self, args):
            """help method for do_show."""
            return """\
Show the attributes of an entry.

Usage: {0} show entry""".format(self.objtype)

        @util.printexceptions
        def do_edit(self, args):
            """Edit the ldif of LDAP object(s) with $EDITOR."""

            edited = origdata = list(self.get_attrs(args))
            # Loop until editing is successful (or cancelled)
            while True:
                try:
                    edited, mods = self.edit(origdata, edited)
                except subprocess.CalledProcessError:
                    print("Editor exited non-zero, aborting.")
                    return
                print("Changes: {0:d} Addition(s), {1:d} Modification(s), {2:d} Deletion(s).".format(len(mods.adds.keys()), len(mods.mods.keys()), len(mods.dels)))
                if any(mods) and safe_to_continue():
                    try:
                        for d_name, val in mods.adds.items():
                            ldconn.conn.add_s(d_name,
                                              ldap.modlist.addModlist(val))
                        for d_name, (oldval, newval) in mods.mods.items():
                            ldconn.conn.modify_s(d_name,
                                                 ldap.modlist.modifyModlist(oldval, newval))
                        for d_name in mods.dels:
                            ldconn.conn.delete_s(d_name)
                        # No exceptions raised - safe to exit the loop
                        break
                    except ldap.LDAPError as exc:
                        # something went wrong - offer the chance to re-edit
                        print("ERROR:%s %s" % (exc.args[0].get('desc', ''), exc.args[0].get('info', '')))
                        if (options.interactive and raw_input(
                            "Do you wish to re-edit? (y/n):").lower().startswith('y')):
                            continue
                        else:
                            break
                else:
                    print("No changes made.")
                    break

        def edit(self, origdata, data):
            """Parse python-ldap results list into ldif, write into a tempfile.
               Launch $EDITOR, then returns saved file contents
               as an equivalent list for processing.
               Finally, compare pre and post-edit data and return diffs."""

            with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as tmpf:
                for entry in data:
                    tmpf.write(ldconn.ldap_to_ldif(entry))
                tmpf.seek(0, 0)
                fcntl.fcntl(tmpf.fileno(), fcntl.F_SETFD, 0)  # clear FD_CLOEXEC
                # Open the tempfile in an editor
                # Errors will cause subprocess.CalledProcessError to be thrown
                subprocess.check_call([os.getenv('EDITOR', "/usr/bin/vi"),
                                          '/dev/fd/{0:d}'.format(
                                              tmpf.fileno())])

                # Parse the ldif to a list of list of tuples, then close tmpf
                tmpf.seek(0, 0)
                edited = [ldconn.ldif_to_ldap(tmpf.read())]

            # Compare the data before and after save
            new_entries = {}
            orig_entries = {}
            for entry in origdata:
                orig_entries.update(dict(entry))
            for entry in edited:
                new_entries.update(dict(entry))
            return edited, util.compare_dicts(orig_entries, new_entries)

        def help_edit(self, args):
            """help method for do_edit."""
            return """\
Open the object(s) in a text editor for editing.
($EDITOR = {0})

Usage: {1} edit entry""".format(os.getenv("EDITOR", "/usr/bin/vi"),
                                self.objtype)

    class LDAPMan(shellac.Shellac):
        """
LDAPMan Shell
-------------

Command-line LDAP Management tool.

- Press <TAB> to see possible command-line completions.
- Type 'help <TAB>' to see which commands have help documentation.
- Type 'exit' or ctrl-d to quit.

        """

        def __init__(self):
            super(LDAPMan, self).__init__()
            if self.stdin.isatty():
                self.prompt = "%s> " % (self.__class__.__name__)

        @objtype("user")
        class do_user(LDAPListCommands):
            """Add a placeholder for a user menu item."""
            pass

        @objtype("group")
        class do_group(LDAPListCommands):
            """Add a group menu item."""

            class do_member(LDAPListCommands):
                """Add a member menu item."""

                def __init__(self):
                    self.do_add.completions = [self.complete_add]
                    self.do_delete.completions = [self.complete_delete]

                def complete_add(self, token=""):
                    """complete method for do_add."""

                    # If the line looks like "group member add gr..." look for
                    # group names to tab complete. If a group name has already
                    # been supplied, tab complete on user names.
                    endidx = shellac.readline.get_endidx()
                    buf = shellac.readline.get_line_buffer()
                    if len(buf[:endidx].split(' ', -1)) >= 5:
                        # Group name given.
                        return self.complete_default(token=token, objtype="user")
                    else:
                        return self.complete_default(token, objtype="group")

                @staticmethod
                @util.printexceptions
                def do_add(args):
                    """add method for group member."""
                    try:
                        group, members = args.split(None, 2)

                        ldconn.ldap_mod_attr("group", "add", "member", group,
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
                             x in ldconn.ldap_attrs("group",
                                                    buf.split(' ', -1)[3]
                                                    )[0][1]['member']], token)
                    else:
                        return ldconn.ldap_search("group", token)

                @staticmethod
                @shellac.completer(partial(ldconn.ldap_search, "group"))
                @util.printexceptions
                @safety_check
                def do_delete(args):
                    """delete method for group member."""
                    try:
                        group, members = args.split(None, 2)

                        ldconn.ldap_mod_attr("group", "delete", "member", group,
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
                @shellac.completer(partial(ldconn.ldap_search, "netgroup"))
                @util.printexceptions
                def do_add(args):
                    """add method for netgroup member."""
                    try:
                        netgroup, members = args.split(None, 2)
                        ldconn.ldap_mod_attr("netgroup", "add",
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
                @shellac.completer(partial(ldconn.ldap_search, "netgroup"))
                @util.printexceptions
                @safety_check
                def do_delete(args):
                    """delete method for netgroup member."""
                    try:
                        netgroup, members = args.split(None, 2)
                        ldconn.ldap_mod_attr("netgroup", "delete",
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
                @shellac.completer(partial(ldconn.ldap_search, "netgroup"))
                @util.printexceptions
                def do_add(args):
                    """add method for netgroup triple."""
                    try:
                        netgroup, triples = args.split(None, 2)
                        ldconn.ldap_mod_attr("netgroup", "add",
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
                @shellac.completer(partial(ldconn.ldap_search, "netgroup"))
                @util.printexceptions
                @safety_check
                def do_delete(args):
                    """delete method for netgroup member."""
                    try:
                        netgroup, triples = args.split(None, 2)
                        ldconn.ldap_mod_attr("netgroup", "delete",
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

            @shellac.completer(partial(ldconn.ldap_search, "automount"))
            @util.printexceptions
            def do_add(self, args):
                """add method for automount."""
                rdn = ''.join([x for x in args.split() if x.startswith('nisMapName')])
                ldconn.ldap_add(self.objtype, args, rdn=rdn)

            @shellac.completer(partial(ldconn.ldap_search, "automount"))
            @util.printexceptions
            def do_modify(self, args):
                """Modify the attributes of an automount object."""
                try:
                    # value may contain spaces, e.g. 'server:/x/y nosuid'
                    obj, attr, value = args.split(' ', 2)
                except ValueError:
                    print("Wrong number of arguments supplied. See help for more information.")
                    return

                # automount objects are children of maps
                # Find the map which the child corresponds to
                try:
                    map_name = next(ldconn.ldap_attrs("automount",
                                                      obj))[0][1]['nisMapName'][0]
                except StopIteration:
                    print("No such object.")
                    return

                ldconn.ldap_replace_attr(self.objtype, obj, attr, value,
                                         rdn="{k}={v}".format(k="nisMapName",
                                                              v=map_name))

            @shellac.completer(partial(ldconn.ldap_search, "automount"))
            @util.printexceptions
            @safety_check
            def do_delete(self, args):
                """delete method for automount."""
                # automount objects are children of maps
                # Find the map which the child corresponds to
                try:
                    map_name = next(ldconn.ldap_attrs("automount",
                                                      args.split()[0]))[0][1]['nisMapName'][0]
                except StopIteration:
                    print("No such object.")
                    return

                ldconn.ldap_delete(self.objtype, args,
                                   rdn="{k}={v}".format(k="nisMapName",
                                                        v=map_name))

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

    # Alter readline's set of completion delim characters to better match
    # what LDAP treats as 'special' characters
    # Best-guess based on: https://www.ietf.org/rfc/rfc4514.txt 2.4
    shellac.readline.set_completer_delims(' \t\n#=+\\",<>')

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
    with ldapsession.LDAPSession(objconf) as ldconn:
        shell = shell_factory(ldconn, config, options, objconf)
        # Override shellac's ctrl_c method to cancel active LDAP operations.
        shell.ctrl_c = lambda x: ldconn.cancel_all()

        if options.interactive:
            shell.onecmd('help')
            shell.cmdloop()
        else:
            shell.onecmd(' '.join(args))
