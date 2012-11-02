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
    ISpiderRequestHandler, ISpiderResponseHandler, \
    ITargetRequestHandler, ITargetResponseHandler

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

    intruderRequest = OrderedExtensionsOption('handlers', 'intruder.request',
         IIntruderRequestHandler, None, False,
         '''List of components implementing the `IIntruderRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Intruder
         sends it on the wire.''')

    intruderResponse = OrderedExtensionsOption('handlers', 'intruder.response',
        IIntruderResponseHandler, None, False,
         '''List of components implementing the `IIntruderResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Intruder
         receives if off the wire.''')

    proxyRequest = OrderedExtensionsOption('handlers', 'proxy.request',
         IProxyRequestHandler, None, False,
         '''List of components implementing the `IProxyRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Proxy
         sends it on the wire.''')

    proxyResponse = OrderedExtensionsOption('handlers', 'proxy.response',
        IProxyResponseHandler, None, False,
         '''List of components implementing the `IProxyResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Proxy
         receives if off the wire.''')

    repeaterRequest = OrderedExtensionsOption('handlers', 'repeater.request',
         IRepeaterRequestHandler, None, False,
         '''List of components implementing the `IRepeaterRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Repeater
         sends it on the wire.''')

    repeaterResponse = OrderedExtensionsOption('handlers', 'repeater.response',
        IRepeaterResponseHandler, None, False,
         '''List of components implementing the `IRepeaterResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Repeater
         receives if off the wire.''')

    scannerRequest = OrderedExtensionsOption('handlers', 'scanner.request',
         IScannerRequestHandler, None, False,
         '''List of components implementing the `IScannerRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Scanner
         sends it on the wire.''')

    scannerResponse = OrderedExtensionsOption('handlers', 'scanner.response',
        IScannerResponseHandler, None, False,
         '''List of components implementing the `IScannerResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Scanner
         receives if off the wire.''')

    sequencerRequest = OrderedExtensionsOption('handlers', 'sequencer.request',
         ISequencerRequestHandler, None, False,
         '''List of components implementing the `ISequencerRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Sequencer
         sends it on the wire.''')

    sequencerResponse = OrderedExtensionsOption('handlers', 'sequencer.response',
        ISequencerResponseHandler, None, False,
         '''List of components implementing the `ISequencerResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Sequencer
         receives if off the wire.''')

    spiderRequest = OrderedExtensionsOption('handlers', 'spider.request',
         ISpiderRequestHandler, None, False,
         '''List of components implementing the `ISpiderRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Spider
         sends it on the wire.''')

    spiderResponse = OrderedExtensionsOption('handlers', 'spider.response',
        ISpiderResponseHandler, None, False,
         '''List of components implementing the `ISpiderResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Spider
         receives if off the wire.''')

    targetRequest = OrderedExtensionsOption('handlers', 'target.request',
         ITargetRequestHandler, None, False,
         '''List of components implementing the `ITargetRequestHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP requests directly before Burp Target
         sends it on the wire.''')

    targetResponse = OrderedExtensionsOption('handlers', 'target.response',
        ITargetResponseHandler, None, False,
         '''List of components implementing the `ITargetResponseHandler`,
         in the order in which they will be applied. These components
         handle processing of HTTP responses directly after Burp Target
         receives if off the wire.''')

    def processHttpMessage(self, toolName, messageIsRequest, messageInfo):
        handlers = ''.join([toolName.lower(),
                            'Request' if messageIsRequest else 'Response'])

        method = ''.join(['process',
                          'Request' if messageIsRequest else 'Response'])

        try:
            request = HttpRequest(messageInfo, _burp=self.burp)
        except Exception:
            self.log.exception('Could not parse object: %r', messageInfo)
            return

        for handler in getattr(self, handlers):
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug('Dispatching handler via %s: %s.%s(%r)',
                               toolName, handler.__class__.__name__,
                               method, request)

            try:
                getattr(handler, method)(request)
            except Exception:
                self.log.exception('Error calling handler via %s: %s.%s(%r)',
                                   toolName, handler.__class__.__name__,
                                   method, request)

        return
