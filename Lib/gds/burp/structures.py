# -*- coding: utf-8 -*-
'''
gds.burp.structures
~~~~~~~~~~~~~~~~~~~

Data structures used by HttpRequest and HttpResponse.

Based on kennethreitz/requests (used with permission). Thanks Kenneth!
'''
from collections import OrderedDict


class CaseInsensitiveDict(OrderedDict):
    """Case-insensitive Dictionary

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header."""

    def __repr__(self):
        return super(CaseInsensitiveDict, self).__repr__()

    def __str__(self):
        return '\r\n'.join(
            ': '.join((key, value)) for key, value in self.iteritems())

    @property
    def lower_keys(self):
        if not hasattr(self, '_lower_keys') or not self._lower_keys:
            self._lower_keys = dict((k.lower(), k) for k in self.iterkeys())
        return self._lower_keys

    def _clear_lower_keys(self):
        if hasattr(self, '_lower_keys'):
            self._lower_keys.clear()

    def __setitem__(self, key, value):
        if key in self:
            del self[key]

        super(CaseInsensitiveDict, self).__setitem__(key, value)
        self._clear_lower_keys()

    def __delitem__(self, key):
        super(CaseInsensitiveDict, self).__delitem__(
            self.lower_keys.get(key.lower(), key))
        self._lower_keys.clear()

    def __contains__(self, key):
        return key.lower() in self.lower_keys

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None
        if key in self:
            return super(CaseInsensitiveDict, self).__getitem__(
                self.lower_keys[key.lower()])

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

class LookupDict(dict):
    """Dictionary lookup object."""

    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __repr__(self):
        return '<lookup \'%s\'>' % (self.name)

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)
