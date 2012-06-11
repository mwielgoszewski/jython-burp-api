# -*- coding: utf-8 -*-
'''
gds.burp.dispatchers
~~~~~~~~~~~~~~~~~~~~

'''
from .api import *
from .core import Component, ExtensionPoint


class NewScanIssueDispatcher(Component):

    dispatchers = ExtensionPoint(INewScanIssueHandler)

    def newScanIssue(self, issue):
        for dispatch in self.dispatchers:
            dispatch.newScanissue(issue)


class PluginDispatcher(Component):

    handlers = {
        'intruder': {
                True: ExtensionPoint(IIntruderRequestHandler),
                False: ExtensionPoint(IIntruderResponseHandler),
            },
        'proxy': {
                True: ExtensionPoint(IProxyRequestHandler),
                False: ExtensionPoint(IProxyResponseHandler),
            },
        'repeater': {
                True: ExtensionPoint(IRepeaterRequestHandler),
                False: ExtensionPoint(IRepeaterResponseHandler),
            },
        'scanner': {
                True: ExtensionPoint(IScannerRequestHandler),
                False: ExtensionPoint(IScannerResponseHandler),
            },
        'sequencer': {
                True: ExtensionPoint(ISequencerRequestHandler),
                False: ExtensionPoint(ISequencerResponseHandler),
            },
        'spider': {
                True: ExtensionPoint(ISpiderRequestHandler),
                False: ExtensionPoint(ISpiderResponseHandler),
            },
        }


    def processHttpMessage(self, toolName, messageIsRequest, request):
        method = ''.join(['process',
                          'Request' if messageIsRequest else 'Response'])

        for handler in self.handlers.get(toolName, {}).get(messageIsRequest, []):
            getattr(handler, method)(request)

        return


