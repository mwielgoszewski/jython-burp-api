# -*- coding: utf-8 -*-
'''
gds.burp.menu.console
~~~~~~~~~~~~~~~~~~~~~

Adds a context menu item to Burp that allows selecting
multiple items in one of Burp's tools and assign it to
the `items` local variable in an interactive session.
'''
from .base import MenuItem
from ..models import HttpRequest


class ConsoleMenu(MenuItem):
    CAPTION = 'assign to local variable `items` in console'

    @staticmethod
    def menuItemClicked(self, menuItemCaption, messageInfo):
        requests = []

        for message in messageInfo:
            requests.append(HttpRequest(message, _burp=self._burp))

        self._burp.console.set('items', requests)

        return
