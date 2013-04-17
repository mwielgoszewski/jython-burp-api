# -*- coding: utf-8 -*-
'''
gds.burp.api
~~~~~~~~~~~~

This module implements the Jython Burp Plugin API.

Plugins written in Jython can implement the interfaces in this
package in order to register for various methods exposed by
Burp Extender.
'''
from .core import Interface


__all__ = [
    'INewScanIssueHandler',
    'IExtenderRequestHandler',
    'IExtenderResponseHandler',
    'IIntruderRequestHandler',
    'IIntruderResponseHandler',
    'IProxyRequestHandler',
    'IProxyResponseHandler',
    'IRepeaterRequestHandler',
    'IRepeaterResponseHandler',
    'IScannerRequestHandler',
    'IScannerResponseHandler',
    'ISequencerRequestHandler',
    'ISequencerResponseHandler',
    'ISpiderRequestHandler',
    'ISpiderResponseHandler',
    'ITargetRequestHandler',
    'ITargetResponseHandler',
]


class INewScanIssueHandler(Interface):
    '''
    Extension point interface for components to perform actions
    whenever Burp Scanner discovers a new, unique issue.

    Classes that implement this interface must implement the
    :meth:`newScanIssue` method.
    '''

    def newScanIssue(issue):
        '''
        This method is invoked whenever Burp Scanner discovers a new,
        unique issue, and can be used to perform customised reporting
        or logging of issues.

        :param issue: An :class:`burp.IScanIssue <IScanIssue>` object.
        '''


class IExtenderRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Extender sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Extender sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IExtenderResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Extender receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Extender receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IIntruderRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Intruder sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Intruder sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IIntruderResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Intruder receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Intruder receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IProxyRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Proxy sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Proxy sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IProxyResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Proxy receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp proxy receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IRepeaterRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Repeater sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Repeater sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IRepeaterResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Repeater receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Repeater receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IScannerRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Scanner sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Scanner sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class IScannerResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Scanner receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Scanner receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class ISequencerRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Sequencer sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Sequencer sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class ISequencerResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Sequencer receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Sequencer receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class ISpiderRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Spider sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Spider sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class ISpiderResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Spider receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Spider receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class ITargetRequestHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a request before Burp Target sends it on the wire.

    Classes that implement this interface must implement the
    :meth:`processRequest` method.
    '''

    def processRequest(request):
        '''
        This method is invoked before Burp Target sends a request
        on the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''


class ITargetResponseHandler(Interface):
    '''
    Extension point interface for components to perform actions on
    a response after Burp Target receives it off the wire.

    Classes that implement this interface must implement the
    :meth:`processResponse` method.
    '''

    def processResponse(request):
        '''
        This method is invoked after Burp Target receives a response
        off the wire.

        :param request: An :class:`HttpRequest <HttpRequest>` object.
        '''
