# -*- coding: utf-8 -*-

'''
gds.burp.models
~~~~~~~~~~~~~~~

This module contains the primary objects that make working with
Burp's IHttpRequestResponse object's more... Pythonic.
'''
import java.lang
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
    def __init__(self, messageInfo, callbacks=None):
        self._messageInfo = messageInfo
        self._request = None
        self._callbacks = callbacks

        self.host = messageInfo.getHost()
        self.port = messageInfo.getPort()
        self.protocol = messageInfo.getProtocol()

        self.method = None
        self.url = None
        self.version = None
        self.headers = CaseInsensitiveDict()
        self.cookies = {}
        self.body = None
        self.response = None

        self.url = urlparse(messageInfo.getUrl().toString())

        if messageInfo.getRequest():
            self._request = messageInfo.getRequest().tostring()

        self.method, self._uri, self.version, self.headers, self.body = \
            _parse_message(self._request)

        self.response = HttpResponse(getattr(messageInfo, 'response', None),
                                     request=self)


    def __len__(self):
        return int(self.headers.get('content-length', len(self.body or '')))


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
        request_headers, _ = self._request.split(CRLF + CRLF, 1)
        return request_headers


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
        except java.lang.Exception:
            print '[*] Could not set comment %s' % (comment,)


class HttpResponse(object):
    def __init__(self, messageInfo, request=None):
        self.request = request

        self.version = None
        self.status_code = None
        self.reason = None
        self.encoding = None
        self.headers = CaseInsensitiveDict()
        self.cookies = {}
        self.body = None

        if messageInfo is not None and hasattr(messageInfo, 'response'):
            self._response = messageInfo.getResponse().tostring()
            self.version, self.status_code, self.reason, self.headers, self.body = \
                _parse_message(messageInfo.getResponse().tostring())

        self._messageInfo = messageInfo


    def __len__(self):
        return int(self.headers.get('content-length', len(self.body or '')))


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
        response_headers , _ = self._response.split(CRLF + CRLF, 1)
        return response_headers


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
        except java.lang.Exception:
            print '[*] Could not set comment %s' % (comment,)


def _parse_message(message):
    request, body = message.split(CRLF + CRLF, 1)
    request_line, request_headers = request.split(CRLF, 1)
    method, uri, http_v = request_line.split(SP, 2)

    headers = CaseInsensitiveDict()
    for request_header in request_headers.split(CRLF):
        header, value = request_header.split(':', 1)
        header = header.strip()
        value = value.strip()
        headers[header] = value

    # if this is a Response object, it'll be:
    # version, status_code, reason, headers, body
    if method.startswith('HTTP/1'):
        return method, int(uri), http_v, headers, body
    else:
        return method, uri, http_v, headers, body
