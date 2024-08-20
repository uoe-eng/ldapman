"""Context manager that connects to an LDAP server and maintain a session.

Provides 'high-level' methods to query and manipulate LDAP data.
"""

import configparser
import base64
import ldap
import ldap.resiter
import ldap.sasl
import ldap.schema
import ldap.modlist
import ldif
import re
import shlex
from io import StringIO


class LDAPObj(ldap.ldapobject.LDAPObject, ldap.resiter.ResultProcessor):
    """Use resiter as a mixin with LDAPObject."""
    pass


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
        self.conn = LDAPObj(self.server)
        try:
            if self.conf.globalconf.getboolean('global', 'use_gssapi'):
                sasl = ldap.sasl.gssapi()
                self.conn.sasl_interactive_bind_s('', sasl)
        except configparser.Error:
            pass

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

        result = []
        for entry in tmpf.getvalue().splitlines():
            # :: as separator means val is base64
            match = re.match(r'^([^:]+):: (.*)$', entry)
            if match:
                entry = "{0}: {1}".format(match.group(1), base64.b64decode(match.group(2)))
            result.append(entry)
        return '\n'.join(result)

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

        try:
            scope = getattr(ldap, self.conf[objtype]['scope'])
        except KeyError:
            scope = ldap.SCOPE_ONELEVEL

        sizelimit = 0
        try:
            sizelimit = self.conf.globalconf.getint('global', 'sizelimit')
        except configparser.Error:
            pass

        if "=" in token:
            # token is attribute=value - use explicitly
            filterstr = token
        else:
            # token is just value - prepend default attribute
            filterstr = "{0}={1}*".format(self.conf[objtype]['filter'],
                                          token)
        # Asynchronous search returns a msg id for later use
        msg_id = self.conn.search_ext(self.conf[objtype]['base'],
                                      scope,
                                      filterstr=filterstr,
                                      sizelimit=sizelimit)
        # allresults generator returns res_type, res_data, res_id, res_controls
        # We only care about res_data
        try:
            for _, res_data, _, _ in self.conn.allresults(msg_id):
                # yield so that we preserve the generator nature of allresults,
                yield res_data
        except ldap.SIZELIMIT_EXCEEDED:
            print("\n...aborted. More than {0} results returned.".format(sizelimit))
            raise StopIteration

    def cancel_all(self):
        """Cancel all active LDAP operations."""
        # Not documented, but works in testing (RES_ANY = -1)
        self.conn.cancel(ldap.RES_ANY)

    def ldap_attrs(self, objtype, token):
        """Get the attributes of an object."""

        try:
            scope = getattr(ldap, self.conf[objtype]['scope'])
        except KeyError:
            scope = ldap.SCOPE_ONELEVEL

        attrlist = []
        try:
            attrlist.extend(self.conf.globalconf.get(objtype, 'attrlist').split(','))
        except configparser.Error:
            pass

        if "=" in token:
            # token is attribute=value - use explicitly
            filterstr = token
        else:
            # token is just value - prepend default attribute
            filterstr = "{0}={1}".format(self.conf[objtype]['filter'],
                                         token)
        msg_id = self.conn.search(self.conf[objtype]['base'],
                                  scope,
                                  filterstr=filterstr,
                                  attrlist=attrlist)

        # allresults returns: res_type, res_data, res_id, res_controls
        # We only care about res_data
        return (x[1] for x in self.conn.allresults(msg_id))

    def ldap_add(self, objtype, args, rdn=""):
        """Add an entry. rdn is an optional prefix to the DN."""

        try:
            attrs = dict([x.split('=', 1) for x in shlex.split(args)])
        except ValueError:
            raise ldap.LDAPError("Invalid attribute(s) specified. (key=value format required).")

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

    def ldap_delete(self, objtype, args, rdn=""):
        """Delete an entry by name."""
        self.conn.delete_s(self.conf.build_dn(args, objtype, rdn))

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
