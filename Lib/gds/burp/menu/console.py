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
