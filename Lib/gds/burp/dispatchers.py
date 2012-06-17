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

from .config import OrderedExtensionsOption
from .core import Component, ExtensionPoint
from .models import HttpRequest

import logging


class NewScanIssueDispatcher(Component):

    dispatchers = ExtensionPoint(INewScanIssueHandler)

    def newScanIssue(self, issue):
        for dispatch in self.dispatchers:
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug('Dispatching new scan issue details via %s',
                               dispatch.__class__.__name__)

            dispatch.newScanIssue(issue)

        return


class PluginDispatcher(Component):

    intruderRequest = OrderedExtensionsOption('plugins', 'intruder.request',
         IIntruderRequestHandler, None, True,
         '''List of components implmenting the `IIntruderRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Intruder
         sends it on the wire.''')

    intruderResponse = OrderedExtensionsOption('plugins', 'intruder.response',
        IIntruderResponseHandler, None, True,
         '''List of components implmenting the `IIntruderResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Intruder
         receives if off the wire.''')

    proxyRequest = OrderedExtensionsOption('plugins', 'proxy.request',
         IProxyRequestHandler, None, True,
         '''List of components implmenting the `IProxyRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Proxy
         sends it on the wire.''')

    proxyResponse = OrderedExtensionsOption('plugins', 'proxy.response',
        IProxyResponseHandler, None, True,
         '''List of components implmenting the `IProxyResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Proxy
         receives if off the wire.''')

    repeaterRequest = OrderedExtensionsOption('plugins', 'repeater.request',
         IRepeaterRequestHandler, None, True,
         '''List of components implmenting the `IRepeaterRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Repeater
         sends it on the wire.''')

    repeaterResponse = OrderedExtensionsOption('plugins', 'repeater.response',
        IRepeaterResponseHandler, None, True,
         '''List of components implmenting the `IRepeaterResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Repeater
         receives if off the wire.''')

    scannerRequest = OrderedExtensionsOption('plugins', 'scanner.request',
         IScannerRequestHandler, None, True,
         '''List of components implmenting the `IScannerRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Scanner
         sends it on the wire.''')

    scannerResponse = OrderedExtensionsOption('plugins', 'scanner.response',
        IScannerResponseHandler, None, True,
         '''List of components implmenting the `IScannerResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Scanner
         receives if off the wire.''')

    sequencerRequest = OrderedExtensionsOption('plugins', 'sequencer.request',
         ISequencerRequestHandler, None, True,
         '''List of components implmenting the `ISequencerRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Sequencer
         sends it on the wire.''')

    sequencerResponse = OrderedExtensionsOption('plugins', 'sequencer.response',
        ISequencerResponseHandler, None, True,
         '''List of components implmenting the `ISequencerResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Sequencer
         receives if off the wire.''')

    spiderRequest = OrderedExtensionsOption('plugins', 'spider.request',
         ISpiderRequestHandler, None, True,
         '''List of components implmenting the `ISpiderRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Spider
         sends it on the wire.''')

    spiderResponse = OrderedExtensionsOption('plugins', 'spider.response',
        ISpiderResponseHandler, None, True,
         '''List of components implmenting the `ISpiderResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Spider
         receives if off the wire.''')


    def processHttpMessage(self, toolName, messageIsRequest, messageInfo):
        handlers = ''.join([toolName.lower(),
                            'Request' if messageIsRequest else 'Response'])

        method = ''.join(['process',
                          'Request' if messageIsRequest else 'Response'])

        request = HttpRequest(messageInfo, _burp=self.burp)

        for handler in getattr(self, handlers):
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug('Dispatching handler via %s: %s.%s(%r)',
                               toolName, handler.__class__.__name__,
                               method, request)

            getattr(handler, method)(request)

        return
