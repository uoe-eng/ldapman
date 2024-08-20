"""Utility functions for ldapman."""

from . import errors

import configparser
from ast import literal_eval
from functools import wraps
from ldap import LDAPError
from optparse import OptionParser
from collections import namedtuple
import os


class LDAPConfig(dict):
    """Store the config data for an LDAPSession object.

    These data come from the config file, with some special processing for
    things which look like lists or dicts.

    Include a convenient method, build_dn, to create a DN given an object class,
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

    def build_dn(self, obj, child=None, rdn=""):
        """ Return a DN constructed from a filter, rdn, and base DN."""
        if len(rdn) != 0:
            rdn += ','
        try:
            conf = self[child] if child is not None else self
        except KeyError:
            # Raise as BuildDNError to allow better handling
            raise errors.BuildDNError
        return "{0}={1},{2}{3}".format(conf['filter'],(obj),
                                       rdn,
                                       conf['base'])


dict_changes = namedtuple("dict_changes", "adds mods dels")


def compare_dicts(olddict, newdict):
    """Compare two dictionaries - return a tuple of dict, dict, set
        - [0] contains 'adds' as k:v
        - [1] contains 'modifies' as k:(oldv,newv)
        - [2] contains 'deletes'

    """

    adds = {}
    mods = {}
    for key, val in newdict.items():
        if key not in olddict:
            adds[key] = val
        elif olddict[key] != newdict[key]:
            mods[key] = (olddict[key], val)
    dels = set(key for key in olddict if key not in newdict)

    return dict_changes(adds, mods, dels)


def get_rdn(obj):
    """Return just the value of the first RDN from a DN.
    e.g. cn=joe,ou=example,ou=com -> joe"""
    return obj[obj.index('=')+1:obj.index(',')]


def parse_config(options):
    """Read in a config file"""

    config = configparser.ConfigParser()
    # Merge (optional) configs from /etc and homedir - last one wins
    config.read(options.config or ['/etc/ldapman.conf',
                                   os.path.join(os.environ.get('HOME',''),
                                                '.ldapman')])
    return config


def parse_opts():
    """Handle command-line arguments"""

    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config",
                      help="Path to configuration file")
    parser.add_option("-f", "--force", dest="force",
                      action="store_true", default=False,
                      help="Don't prompt for confirmation for operations")
    return parser.parse_args()


def printexceptions(func):
    """Decorate the given function so that in debugging mode all unhandled
    tracebacks are printed and re-raised.

    """

    @wraps(func)
    def new_func(*args, **kwargs):
        """function returned by the decorator."""

        try:
            return func(*args, **kwargs)
        # Certain errors should be reported, but not raised
        # This gives an error message, but remains in the shell
        except LDAPError as exc:
            # LDAPError may contain a dict with desc and (optional) info fields
            if isinstance(exc.args[0], dict):
                print(exc.args[0]['desc'], exc.args[0].get('info', ''))
            else:
                # Otherwise, treat as a simple string
                print(exc)
        except (configparser.ParsingError, errors.BuildDNError) as exc:
            print(exc)
        # Otherwise, print and raise exceptions if debug is enabled
        except Exception as exc:
            # FIXME: test for debug flag
            print(exc)
            raise
    return new_func
