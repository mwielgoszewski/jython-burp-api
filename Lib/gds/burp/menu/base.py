# -*- coding: utf-8 -*-
'''
gds.burp.menu.base
~~~~~~~~~~~~~~~~~~

Base MenuItem class that all MenuItemHandlers will 
inherit from.
'''
from burp import IMenuItemHandler


class MenuItem(IMenuItemHandler):
    CAPTION = ''

    def __init__(self, _burp):
        self._burp = _burp
        self._burp.registerMenuItem(self.CAPTION, self)
        self._burp.issueAlert('registered menu item: %r' % (self.CAPTION,))


