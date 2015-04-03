"""ldapman.errors

Provides exceptions used by the ldapman modules."""


class BuildDNError(Exception):
    """Errors when constructing a DN in BuildDN method."""

    def __init__(self, args="Error building a DN from supplied arguments."):
        Exception.__init__(self, args)
