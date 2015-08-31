"""Context manager that connects to an LDAP server and maintain a session.

Provides 'high-level' methods to query and manipulate LDAP data.
"""

from . import util

import ConfigParser
import io
import ldap
import ldap.sasl
import ldap.schema
import ldap.modlist
import ldif
import shellac
from StringIO import StringIO


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

    @staticmethod
    def ldap_to_ldif(pyld):
        """Convert python-ldap list of tuples into ldif string"""

        tmpf = StringIO()
        ldw = ldif.LDIFWriter(tmpf, cols=99999)
        for item in pyld:
            ldw.unparse(*item)

        return tmpf.getvalue()

    @staticmethod
    def ldif_to_ldap(ldiff):
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

        timeout = -1
        try:
            timeout = float(self.conf.globalconf.get('global', 'timeout'))
        except ConfigParser.Error:
            pass
        try:
            scope = getattr(ldap, self.conf[objtype]['scope'])
        except KeyError:
            scope = ldap.SCOPE_ONELEVEL
        try:
            result = self.conn.search_st(self.conf[objtype]['base'],
                                         scope,
                                         filterstr="{0}={1}*".format(
                                             self.conf[objtype]['filter'],
                                             token),
                                         timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

        # Result is a list of tuples, first item of which is DN
        # Strip off the base, then parition on = and keep value
        # Could alternatively split on = and keep first value?
        return [util.get_rdn(x[0]) for x in result]

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
                                       filterstr="{0}={1}".format(
                                           self.conf[objtype]['filter'],
                                           token),
                                       timeout=timeout)
        except ldap.TIMEOUT:
            raise shellac.CompletionError("Search timed out.")

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
                "Missing mandatory attribute(s): {0}".format(','.join(missing)))

        # Convert the attrs dict into ldif
        ldiff = ldap.modlist.addModlist(attrs)

        d_name = self.conf.build_dn(
            attrs[self.conf[objtype]['filter'].partition('=')[0]],
            objtype, rdn=rdn)
        self.conn.add_s(d_name, ldiff)

    def ldap_delete(self, objtype, args):
        """Delete an entry by name."""
        self.conn.delete_s(self.conf.build_dn(args, objtype))

    def ldap_rename(self, objtype, args):
        """Rename an object. args must be 'name newname'."""

        name, newname = args.split()

        self.conn.rename_s(self.conf.build_dn(name, objtype),
                           self.conf[objtype]['filter'] % (newname))

    def ldap_mod_attr(self, objtype, modmethod, attr, obj, items):
        """Modify an attribute.

        objtype refers to a config section (for DN root).
        modmethod can be add or delete.
        attr is the name of the attribute(s) to be modified.
        obj is the object whose attribute we're modifying.
        items is a list of values to create/set attributes to."""

        self.conn.modify_s(self.conf.build_dn(obj, child=objtype),
                           [(getattr(ldap, "MOD_" + modmethod.upper()),
                             attr, item) for item in items])

    def ldap_replace_attr(self, objtype, obj, attr, value, rdn=""):
        """Replace the value of an object attribute."""

        self.conn.modify_s(self.conf.build_dn(obj, child=objtype, rdn=rdn),
                           [(ldap.MOD_REPLACE, attr, value)])
