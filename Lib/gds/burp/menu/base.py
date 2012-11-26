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
        self.burp = self._burp = _burp
        self.log = self.burp.log
        self.burp.registerMenuItem(self.CAPTION, self)
        self.burp.issueAlert('Registered menu item: %r' % (self.CAPTION, ))

    def menuItemClicked(self, menuItemCaption, messageInfo):
        raise NotImplementedError
