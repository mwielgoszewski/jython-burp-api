# -*- coding: utf-8 -*-
'''
gds.burp.menu.console
~~~~~~~~~~~~~~~~~~~~~

Adds a context menu item to Burp that allows selecting
multiple items in one of Burp's tools and assign it to
the `items` local variable in an interactive session.
'''
from burp import IMenuItemHandler
from ..models import HttpRequest


class ConsoleMenuItem(IMenuItemHandler):
    CAPTION = 'assign to local variable `items` in console'

    def __init__(self, _burp):
        self._burp = _burp
        self._burp.registerMenuItem(self.CAPTION, self)
        self._burp.issueAlert('registered menu item: %r' % (self.CAPTION,))


    def menuItemClicked(self, menuItemCaption, messageInfo):
        requests = []

        for message in messageInfo:
            requests.append(HttpRequest(message,
                                        callbacks=self._burp.cb))

        self._burp.console.set('items', requests)

        return
