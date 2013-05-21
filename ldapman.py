#!/usr/bin/python

import shellac

# Might not need all 3?
import ldap
import ldap.sasl
import sys
import ConfigParser
from optparse import OptionParser
from contextlib import closing


def ldap_user_search(token):
    return ldap_search(token,
                       self.get_conf(peoplebase),
                       self.get_conf(peoplefilter))

def ldap_group_search(token):
    return ldap_search(token,
                       self.get_conf(groupbase),
                       self.get_conf(groupfilter))

def ldap_search(token, base, filter):
    # FIX: try/except needed only for explicit errs during testing
    try:
        result = self._conn.search(base,
                                   ldap.SCOPE_SUBTREE,
                                   searchFilter = filter % (token))
        result_type, result_data = self._conn.result(result, 0)
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

    (options, args) = parser.parse_args()

    return options


def parse_config(options):
    """Read in a config file"""

    config = ConfigParser.SafeConfigParser()
    # FIX: Change to a better default
    config_file = 'ldapman.conf'
    if options.config:
        config_file = options.config
    config.read(config_file)

    return config


class LDAPMan(shellac.Shellac, object):

    def __init__(self, options, config):
        super(LDAPMan, self).__init__()
        self._conn = None
        self.closed = True
        self.options = options
        self.config = config

    def open(self):
        server = self.get_conf('server')
        self._conn = ldap.initialize(server)
        sasl = ldap.sasl.gssapi()
        self._conn.sasl_interactive_bind_s('', sasl)
        self.closed = False

    def close(self):
        if not self.closed:
            self._conn.unbind_s()
            self.closed = True

    def get_conf(self, item):
        """Get configuration from either cmd-line or config file"""

        opt = None
        try:
            opt = getattr(self.options, item)
        except AttributeError:
            # Might not be a cmd-line option at all!
            pass
        if opt is None:
            # Read from config file
            opt = self.config.get('global', item)
        return opt

    class do_group():

        def do_add(self, args):
            print("Added group: ", args)

        @shellac.completer(ldap_search)
        def do_edit(self, args):
            print("Edited group: ", args)

        @shellac.completer(ldap_search)
        def do_search(self, args):
            pass


def main():
    options = parse_opts()
    config = parse_config(options)
    with closing(LDAPMan(options, config)) as ld:
        ld.open()
        ld.cmdloop()


if __name__ == "__main__":
    main()
