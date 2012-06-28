# -*- coding: utf-8 -*-
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from array import array
import json

from gds.burp.models import HttpRequest
from gds.burp.menu import MenuItem

encoder = json.JSONEncoder(separators=(',', ':'))


class JSONIntruderMenu(MenuItem):
    CAPTION = 'send to intruder (json request)'

    def menuItemClicked(self, menuItemCaption, messageInfo):
        for message in messageInfo:
            request = HttpRequest(message, _burp=self.burp)

            if 'json' not in request.content_type:
                continue

            body = StringIO()
            body.write(request.raw.split('\r\n\r\n', 1)[0])
            body.write('\r\n\r\n')

            print 'blah'

            try:
                message, offsets = encode(body, json.loads(request.body))
            except Exception:
                self.log.exception('Error decoding json body: %r',
                    request.body)

            self.burp.sendToIntruder(
                request.host, request.port, request.is_secure,
                message, offsets)

        return


class JSONActiveScannerMenu(MenuItem):
    CAPTION = 'actively scan this item (json request)'

    def menuItemClicked(self, menuItemCaption, messageInfo):
        for message in messageInfo:
            request = HttpRequest(message, _burp=self.burp)

            if 'json' not in request.content_type:
                continue

            body = StringIO()
            body.write(request.raw.split('\r\n\r\n', 1)[0])
            body.write('\r\n\r\n')

            try:
                message, offsets = encode(body, json.loads(request.body))
            except Exception:
                self.log.exception('Error decoding json body: %r',
                    request.body)

            self.burp.doActiveScan(
                request.host, request.port, request.is_secure,
                message, offsets)

        return


def encode(fileobj, jsonobj):
    offsets = []

    dict_level = 0
    list_level = 0
    at_key = False
    at_value = False

    for s in encoder.iterencode(jsonobj):
        if s == '{':
            dict_level += 1
            at_key = True
            at_value = False
            fileobj.write(s)
            continue

        elif s == '}':
            dict_level -= 1
            at_value = False
            at_key = False
            fileobj.write(s)
            continue

        elif s == '[':
            list_level += 1
            fileobj.write(s)
            continue

        elif s == ']':
            list_level -= 1
            at_value = False
            fileobj.write(s)
            continue

        elif s == ':':
            at_key = False
            at_value = True
            fileobj.write(s)
            continue

        elif s == ',':
            if dict_level > 0:
                at_value = False

            fileobj.write(s)
            continue

        else:
            if at_value or (s.startswith('[') and len(s) > 1) or \
                (s.startswith(',') and len(s) > 1):

                if s.startswith('['):
                    list_level += 1

                if s.startswith(('["', ',"')):
                    start = fileobj.tell() + 2

                elif s.startswith(('[', ',', '"')):
                    start = fileobj.tell() + 1

                else:
                    start = fileobj.tell()

                fileobj.write(s)

                if s.endswith('"'):
                    end = fileobj.tell() - 1
                else:
                    end = fileobj.tell()

                offsets.append(array('i', (start, end)))

            else:
                fileobj.write(s)

    return fileobj.getvalue(), offsets
