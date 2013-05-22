#!/usr/bin/python

import shellac

# Might not need all 3?
import ldap
import ldap.sasl
import sys
import ConfigParser
from optparse import OptionParser
from contextlib import closing


class LDAPSession(object):

    def __init__(self, options, config):
        self._conn = None
        self.closed = True
        self.options = options
        self.config = config

    def open(self):
        server = get_conf('server')
        self._conn = ldap.initialize(server)
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

    def ldap_user_search(self, token):
        return ldap_search(self, token,
                           get_conf(peoplebase),
                           get_conf(peoplefilter))

    def ldap_group_search(self, token):
        return ldap_search(token,
                           get_conf(groupbase),
                           get_conf(groupfilter))

    def ldap_search(self, token, base, filterstr):
        # FIX: try/except needed only for explicit errs during testing
        try:
            result = self._conn.search_s(base,
                                         ldap.SCOPE_SUBTREE,
                                         filterstr=filterstr % (token))
            result_data = self._conn.result(result, 0)
            print result_data
        except Exception as e:
            print e


def parse_opts():
    """Handle command-line arguments"""

    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config",
                      help="Path to configuration file")
    parser.add_option("-s", "--server", dest="server",
                      help="LDAP server URI")
    parser.add_option("-b", "--base", dest="base",
                      help="LDAP base")

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


def get_conf(item):
    """Get configuration from either cmd-line or config file."""

    opt = options.__dict__.get(item)
    if opt is None:
        # Read from config file
        opt = config.get('global', item)
    return opt


def main():
    with LDAPSession(options, config) as ld:
        class LDAPShell(shellac.Shellac, object):
            class do_group():

                def do_add(self, args):
                    print("Added group: ", args)

                @shellac.completer(ld.ldap_group_search)
                def do_edit(self, args):
                    print("Edited group: ", args)

                @shellac.completer(ld.ldap_group_search)
                def do_search(self, args):
                    pass

        if len(args) != 0:
            LDAPShell().onecmd(' '.join(args))
        else:
            LDAPShell().cmdloop()


options, args = parse_opts()
config = parse_config(options)


if __name__ == "__main__":
    main()
