# -*- coding: utf-8 -*-

'''
gds.burp.models
~~~~~~~~~~~~~~~

This module contains the primary objects that make working with
Burp's IHttpRequestResponse object's more... Pythonic.
'''
try:
    from java.lang import Exception as JavaException
except ImportError:
    # running under CPython
    JavaException = Exception

from Cookie import SimpleCookie
from cgi import parse_header, parse_qs
from urlparse import urlparse

from .structures import CaseInsensitiveDict


CRLF = '\r\n'
SP = chr(0x20)


class HttpRequest(object):
    '''The :class:`HttpRequest <HttpRequest>` object. Pass Burp's
    IHttpRequestResponse object to the constructor.

    Optional init arguments:
    :param callbacks: IBurpExtenderCallbacks
    '''
    def __init__(self, messageInfo=None, callbacks=None):
        self._messageInfo = messageInfo
        self._request = None
        self._callbacks = callbacks

        self.host = None
        self.port = 80
        self.protocol = 'http'
        self.url = urlparse('')

        self.method = None
        self._uri = None
        self.version = None
        self.headers = CaseInsensitiveDict()
        self.cookies = SimpleCookie()
        self.body = None

        if messageInfo is not None and hasattr(messageInfo, 'request'):
            self.host = messageInfo.getHost()
            self.port = messageInfo.getPort()
            self.protocol = messageInfo.getProtocol()
            self.url = urlparse(messageInfo.getUrl().toString())

            if messageInfo.getRequest():
                self._request = messageInfo.getRequest().tostring()

                self.method, self._uri, self.version, self.headers, self.body = \
                    _parse_message(self._request)

        self.parameters = _parse_parameters(self)
        self.cookies.load(self.headers.get('cookie', ''))

        if hasattr(messageInfo, 'response'):
            self.response = HttpResponse(getattr(messageInfo, 'response', None),
                                         request=self)
        else:
            self.response = HttpResponse(None, request=self)


    def __contains__(self, item):
        return item in self.body if self.body else False


    def __len__(self):
        return int(self.headers.get('content-length', len(self.body or '')))


    def __nonzero__(self):
        return self._request is not None


    def __repr__(self):
        return '<HttpRequest [%s]>' % (self.url.path,)


    @property
    def content_type(self):
        '''
        Content-Type of the HTTP request.
        '''
        return self.headers.get('content-type', '')


    @property
    def is_secure(self):
        '''
        True if the HTTP request was sent over HTTPS.
        '''
        return True if self.protocol == 'https' else False


    @property
    def raw(self):
        '''
        Returns the raw, unparsed HTTP request.
        '''
        return self._request


    @property
    def raw_headers(self):
        '''
        Returns just the raw, unparsed HTTP request headers.
        '''
        if self._request:
            request_headers, _ = self._request.split(CRLF + CRLF, 1)
            return request_headers

        return


    def add_comment(self, comment, append=True):
        '''
        Helper method to add comment to underlying IHttpRequestResponse
        object.

        :param comment: the comment
        :param append: if True, append comment to existing comment if any.
        '''
        try:
            if append is True:
                _comment = self._messageInfo.getComment()
                if _comment:
                    comment = '%s, %s' % (_comment, comment)
                self._messageInfo.setComment(comment)
            else:
                self._messageInfo.setComment(comment)
        except JavaException, reason:
            print '[*] Could not set comment %s: %s' % (comment, reason,)

        return


    @property
    def highlight(self):
        '''
        Get color of the underlying IHttpRequestResponse object.
        '''
        if self._messageInfo:
            return self._messageInfo.getHighlight()

        return


    @highlight.setter
    def highlight(self, color):
        '''
        Set color of the underlying IHttpRequestResponse object.

        colors: red, orange, yellow, green, cyan, blue, pink, magenta, gray
        '''
        if self._messageInfo:
            self._messageInfo.setHighlight(color)

        return


class HttpResponse(object):
    def __init__(self, messageInfo=None, request=None):
        self._response = None
        self.request = request

        self.version = None
        self.status_code = None
        self.reason = None
        self.encoding = None
        self.headers = CaseInsensitiveDict()
        self.cookies = SimpleCookie()
        self.body = None

        if messageInfo is not None:
            self._response = messageInfo.tostring()
            self.version, self.status_code, self.reason, self.headers, self.body = \
                _parse_message(self._response)

        self.cookies.load(self.headers.get('set-cookie', ''))


    def __contains__(self, item):
        return item in self.body if self.body else False


    def __len__(self):
        return int(self.headers.get('content-length', len(self.body or '')))


    def __nonzero__(self):
        return self._response is not None


    def __repr__(self):
        return '<HttpResponse [%s]>' % (self.status_code, )


    @property
    def content_type(self):
        '''
        Content-Type of the HTTP response.
        '''
        return self.headers.get('content-type', '')


    @property
    def raw(self):
        '''
        Returns the raw, unparsed HTTP response.
        '''
        return self._response


    @property
    def raw_headers(self):
        '''
        Returns just the raw, unparsed HTTP response headers.
        '''
        if self._response:
            response_headers , _ = self._response.split(CRLF + CRLF, 1)
            return response_headers

        return


    def add_comment(self, comment, append=True):
        '''
        Helper method to add comment to underlying IHttpRequestResponse
        object.

        :param comment: the comment
        :param append: if True, append comment to existing comment if any.
        '''
        try:
            self.request.add_comment(comment, append=append)
        except JavaException, reason:
            print '[*] Could not set comment %s: %s' % (comment, reason,)

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
                raise ValueError('status code %r is not a number' % (status,))

            status = int(status)

            _pos = _idx + 1
            reason = start_line[_pos:]

        else:
            # work out the http version by looking in reverse
            _ridx = start_line.rfind(SP)
            version = start_line[_ridx + 1:]
            if not version.startswith('HTTP/'):
                raise ValueError('Invalid HTTP version: %r' % (version,))

            # request-uri will be everything in-between.
            # some clients might not encode space into a plus or %20
            uri = start_line[_pos:_ridx]
            if not uri or uri.isspace():
                raise ValueError('Invalid URI: %r' % (uri,))

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
                value = header[_idx+1:].strip()

                has_value = headers.get(name)

                if has_value and has_value != value:
                    value = ', '.join([has_value, value])

                headers[name] = value
            else:
                raise ValueError('Error parsing header: %r' % (header,))

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
        parameters['query'] = parse_qs(request.url.query, keep_blank_values=True)

    _type, _options = parse_header(request.headers.get('content-type', ''))

    if _type == 'application/x-www-form-urlencoded':
        parameters['body'] = parse_qs(request.body, keep_blank_values=True)

    elif _type in ('application/json', ):
        try:
            parameters['body'] = json.loads(request.body)
        except (NameError, TypeError):
            pass

    elif _type == 'application/x-amf':
        pass

    elif _type == 'text/x-gwt-rpc':
        pass

    elif _type == 'application/xml':
        pass

    else:
        pass

    return parameters
