# -*- coding: utf-8 -*-
'''
gds.burp.dispatchers
~~~~~~~~~~~~~~~~~~~~

'''
from .api import INewScanIssueHandler, \
    IIntruderRequestHandler, IIntruderResponseHandler, \
    IProxyRequestHandler, IProxyResponseHandler, \
    IRepeaterRequestHandler, IRepeaterResponseHandler, \
    IScannerRequestHandler, IScannerResponseHandler, \
    ISequencerRequestHandler, ISequencerResponseHandler, \
    ISpiderRequestHandler, ISpiderResponseHandler

from .core import Component, ExtensionPoint


class NewScanIssueDispatcher(Component):

    dispatchers = ExtensionPoint(INewScanIssueHandler)

    def newScanIssue(self, issue):
        for dispatch in self.dispatchers:
            if self.burp.opt.debug:
                self.log.debug('Dispatching new scan issue details via %s',
                               dispatch.__class__.__name__)

            dispatch.newScanIssue(issue)

        return


class PluginDispatcher(Component):

    intruderRequest = ExtensionPoint(IIntruderRequestHandler)
    intruderResponse = ExtensionPoint(IIntruderResponseHandler)

    proxyRequest = ExtensionPoint(IProxyRequestHandler)
    proxyResponse = ExtensionPoint(IProxyResponseHandler)

    repeaterRequest = ExtensionPoint(IRepeaterRequestHandler)
    repeaterResponse = ExtensionPoint(IRepeaterResponseHandler) 

    scannerRequest = ExtensionPoint(IScannerRequestHandler)
    scannerResponse = ExtensionPoint(IScannerResponseHandler)

    sequencerRequest = ExtensionPoint(ISequencerRequestHandler)
    sequencerResponse = ExtensionPoint(ISequencerResponseHandler)

    spiderRequest = ExtensionPoint(ISpiderRequestHandler)
    spiderResponse = ExtensionPoint(ISpiderResponseHandler)


    def processHttpMessage(self, toolName, messageIsRequest, request):
        handlers = ''.join([toolName,
                            'Request' if messageIsRequest else 'Response'])

        method = ''.join(['process',
                          'Request' if messageIsRequest else 'Response'])

        for handler in getattr(self, handlers):
            if self.burp.opt.debug:
                self.log.debug('Dispatching handler via %s: %s.%s(%r)',
                               toolName, handler.__class__.__name__,
                               method, request)

            getattr(handler, method)(request)

        return
