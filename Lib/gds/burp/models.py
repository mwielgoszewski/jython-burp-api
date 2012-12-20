# -*- coding: utf-8 -*-
'''
gds.burp.models
~~~~~~~~~~~~~~~

This module contains the primary objects that make working with
Burp's IHttpRequestResponse object's more... Pythonic.
'''
from Cookie import SimpleCookie
from cStringIO import StringIO
from cgi import FieldStorage, parse_header, parse_qs
from urlparse import urlparse

from .decorators import reify
from .structures import CaseInsensitiveDict

import json

CRLF = '\r\n'
SP = chr(0x20)


class HttpRequest(object):
    '''The :class:`HttpRequest <HttpRequest>` object. Pass Burp's
    IHttpRequestResponse object to the constructor.

    Optional init arguments:
    :param _burp: IBurpExtender implementation
    '''
    def __init__(self, messageInfo=None, _burp=None):
        self._messageInfo = messageInfo
        self._burp = _burp

        self._host = None
        self._port = 80
        self._protocol = 'http'
        self._url = ''

        self.method = None
        self._uri = None
        self.version = None
        self._headers = {}
        self.body = None

        if messageInfo is not None and hasattr(messageInfo, 'request'):
            if messageInfo.getRequest():
                self.method, self._uri, self.version, self._headers, self.body = \
                    _parse_message(messageInfo.getRequest().tostring())

        if hasattr(messageInfo, 'response'):
            self.response = HttpResponse(getattr(messageInfo, 'response', None),
                                         request=self)
        else:
            self.response = HttpResponse(None, request=self)

    def __contains__(self, item):
        return item in self.body if self.body else False

    def __getstate__(self):
        return {k: v if k not in ('_burp', '_messageInfo') else None
                for k, v in self.__dict__.iteritems()}

    def __len__(self):
        return int(self.headers.get('content-length', len(self.body or '')))

    def __nonzero__(self):
        return self.raw is not None

    def __repr__(self):
        return '<HttpRequest [%s]>' % (getattr(self.url, 'path', ''), )

    @property
    def host(self):
        '''
        Returns the name of the application host.
        '''
        if self._messageInfo is not None and \
            self._host != self._messageInfo.getHost():
            self._host = self._messageInfo.getHost()

        return self._host

    @host.setter
    def host(self, host):
        '''
        Sets the name of the application host to which the request
        should be sent.

        Note: This method generally can only be used before the
        message has been forwarded to the application, and not in
        read-only contexts.

        :param host: The name of the application host to which the
        request should be sent.
        '''
        if self._messageInfo is not None:
            self._messageInfo.setHost(host)

        return

    @property
    def port(self):
        '''
        Returns the port number used by the application.
        '''
        if self._messageInfo is not None and \
            self._port != self._messageInfo.getPort():
            self._port = self._messageInfo.getPort()

        return self._port

    @port.setter
    def port(self, port):
        '''
        Sets the port number to which the request should be sent.

        Note: This method generally can only be used before the
        message has been forwarded to the application, and not in
        read-only contexts.

        :param port: The port number to which the request should be
        sent.
        '''
        if self._messageInfo is not None:
            self._messageInfo.setPort(port)

        return

    @property
    def protocol(self):
        '''
        Returns the protocol used by the application.
        '''
        if self._messageInfo is not None and \
            self._protocol != self._messageInfo.getProtocol():
            self._protocol = self._messageInfo.getProtocol()

        return self._protocol

    @protocol.setter
    def protocol(self, protocol):
        '''
        Sets the protocol which should be used by the request.

        Note: This method generally can only be used before the
        message has been forwarded to the application, and not in
        read-only contexts.

        :param protocol: The protocol which should be used by the
        request. Valid values are "http" and "https".
        '''
        if self._messageInfo is not None:
            self._messageInfo.setProtocol(protocol)

        return

    @reify
    def url(self):
        '''
        The URL requested in this HTTP request.

        Note: This is a **read-only** attribute.

        :returns: :class:`~urlparse.ParseResult` object.
        '''
        if self._messageInfo is not None:
            self._url = urlparse(self._messageInfo.getUrl().toString())

        return self._url

    @reify
    def cookies(self):
        '''
        The HTTP Cookies sent in this request.

        Note: This is a **read-only** attribute.

        :returns: :class:`~Cookie.SimpleCookie` object.
        '''
        self._cookies = SimpleCookie(self.headers.get('cookie', ''))
        return self._cookies

    @reify
    def headers(self):
        '''
        The HTTP headers sent in this request. Headers are accessible
        by their header names (case insensitive).

        Note: This is a **read-only** attribute.
        '''
        self._headers = CaseInsensitiveDict(self._headers)
        return self._headers

    @reify
    def parameters(self):
        '''
        Parameters parsed into a dictionary based on type (i.e., query,
        body, etc.)

        Note: This is a **read-only** attribute.
        '''
        self._parameters = _parse_parameters(self)
        return self._parameters

    @property
    def content_type(self):
        '''
        Content-Type of the HTTP request.

        Note: This is a **read-only** attribute.
        '''
        return self.headers.get('content-type', '')

    @property
    def is_secure(self):
        '''
        True if the HTTP request was sent over HTTPS.

        Note: This is a **read-only** attribute.
        '''
        return True if self.protocol == 'https' else False

    @property
    def is_xhr(self):
        '''
        True if the HTTP request originated on the client using
        XMLHttpRequest.

        Note: This is a **read-only** attribute.
        '''
        return True if 'x-requested-with' in self.headers else False

    @property
    def raw(self):
        '''
        Returns the full request contents.
        '''
        if self._messageInfo:
            return self._messageInfo.getRequest().tostring()

        return

    @raw.setter
    def raw(self, message):
        '''
        Sets the request contents which should be sent to the application.

        :param message: The request contents which should be sent to the
        application.
        '''
        if self._messageInfo:
            self._messageInfo.setRequest(message)

        return

    @property
    def comment(self):
        '''
        Returns the user-annotated comment for this item, if applicable.
        '''
        if self._messageInfo:
            return self._messageInfo.getComment()

        return

    @comment.setter
    def comment(self, comment):
        '''
        Sets the user-annotated comment for this item.

        :param comment: The comment to be associated with this item.
        '''
        if self._messageInfo:
            return self._messageInfo.setComment(comment)

        return

    @property
    def highlight(self):
        '''
        Returns the user-annotated color for this item, if applicable.
        '''
        if self._messageInfo:
            return self._messageInfo.getHighlight()

        return

    @highlight.setter
    def highlight(self, color):
        '''
        Sets the user-annotated color for this item.

        :param color: The color to be associated with this item.
        Valid values are: red, orange, yellow, green, cyan, blue, pink,
        magenta, gray.
        '''
        if self._messageInfo:
            self._messageInfo.setHighlight(color)

        return


class HttpResponse(object):
    def __init__(self, message=None, request=None):
        self.request = request

        self.version = None
        self.status_code = None
        self.reason = None
        self.encoding = None
        self._headers = {}
        self.body = None

        if message is not None:
            self.version, self.status_code, self.reason, self._headers, self.body = \
                _parse_message(message.tostring())

    def __contains__(self, item):
        return item in self.body if self.body else False

    def __len__(self):
        return int(self.headers.get('content-length', len(self.body or '')))

    def __nonzero__(self):
        return self.raw is not None

    def __repr__(self):
        return '<HttpResponse [%s]>' % (self.status_code, )

    @reify
    def cookies(self):
        '''
        The HTTP Cookies set in this response.

        Note: This is a **read-only** attribute.

        :returns: :class:`~Cookie.SimpleCookie` object.
        '''
        self._cookies = SimpleCookie(self.headers.get('set-cookie', ''))
        return self._cookies

    @reify
    def headers(self):
        '''
        The HTTP headers received in this response. Headers are accessible
        by their header names (case insensitive).

        Note: This is a **read-only** attribute.
        '''
        self._headers = CaseInsensitiveDict(self._headers)
        return self._headers

    @property
    def content_type(self):
        '''
        Content-Type of the HTTP response.

        Note: This is a **read-only** attribute.
        '''
        return self.headers.get('content-type', '')

    @property
    def raw(self):
        '''
        Returns the full response contents.
        '''
        if self.request._messageInfo:
            return self.request._messageInfo.getResponse().tostring()

        return

    @raw.setter
    def raw(self, message):
        '''
        Sets the response contents which should be processed by the
        invoking Burp tool.

        :param message: The response contents which should be processed
        by the invoking Burp tool.
        '''
        if self.request._messageInfo:
            return self.request._messageInfo.setResponse(message)

        return


def _parse_message(message):
    is_response = False
    pos = idx = 0

    idx = message.find(CRLF, pos)

    if idx != -1:
        start_line = message[pos:idx]

        if start_line.startswith('HTTP/'):
            is_response = True

        _idx = start_line.find(SP)

        if _idx != -1:
            if is_response:
                version = start_line[0:_idx]
            else:
                method = start_line[0:_idx]

            _pos = _idx + 1

        if is_response:
            _idx = start_line.find(SP, _pos)

            status = start_line[_pos:_idx]
            if not status.isdigit():
                raise ValueError('status code %r is not a number' % (status, ))

            status = int(status)

            _pos = _idx + 1
            reason = start_line[_pos:]

        else:
            # work out the http version by looking in reverse
            _ridx = start_line.rfind(SP)
            version = start_line[_ridx + 1:]
            if not version.startswith('HTTP/'):
                raise ValueError('Invalid HTTP version: %r' % (version, ))

            # request-uri will be everything in-between.
            # some clients might not encode space into a plus or %20
            uri = start_line[_pos:_ridx]
            if not uri or uri.isspace():
                raise ValueError('Invalid URI: %r' % (uri, ))

        pos = idx + 2
    else:
        raise ValueError('Could not parse start-line from message')

    headers = CaseInsensitiveDict()

    while (idx != -1):
        idx = message.find(CRLF, pos)

        if idx == pos:
            # we've reached the end of the request headers
            # advance 4 bytes (2 * CRLF)
            pos = idx + 2
            break

        if idx != -1:
            header = message[pos:idx]
            _idx = header.find(':')

            if _idx != -1:
                name = header[:_idx].strip()
                value = header[_idx + 1:].strip()

                has_value = headers.get(name)

                if has_value and has_value != value:
                    value = ', '.join([has_value, value])

                headers[name] = value
            else:
                raise ValueError('Error parsing header: %r' % (header, ))

            pos = idx + 2
        else:
            # looks like we reached the end of the message before EOL
            break

    if idx < len(message):
        body = message[pos:]
    else:
        raise ValueError('Parsed past message body??')

    if not is_response:
        return method, uri, version, headers, body
    else:
        return version, status, reason, headers, body


def _parse_parameters(request):
    parameters = {}

    if request.url.query:
        parameters['query'] = parse_qs(request.url.query,
                                       keep_blank_values=True)

    ctype, pdict = parse_header(request.headers.get('content-type', ''))

    if ctype == 'application/x-www-form-urlencoded':
        parameters['body'] = parse_qs(request.body, keep_blank_values=True)

    elif ctype.startswith('multipart/'):
        parameters['body'] = FieldStorage(
            fp=StringIO(request.body),
            headers=request.headers,
            environ={
                REQUEST_METHOD: request.method,
                QUERY_STRING: request.url.query,
                },
            keep_blank_values=True)

    elif ctype in ('application/json', ):
        try:
            parameters['body'] = json.loads(request.body)
        except (NameError, TypeError):
            pass

    elif ctype == 'application/x-amf':
        pass

    elif ctype == 'text/x-gwt-rpc':
        pass

    elif ctype == 'application/xml':
        pass

    else:
        pass

    return parameters
