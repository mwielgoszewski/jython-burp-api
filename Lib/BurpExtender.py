# -*- coding: utf-8 -*-

'''
BurpExtender
~~~~~~~~~~~~

BurpExtender is a proxied class that implements the burp.IBurpExtender
interface. It is what makes Jython <-> Burp possible.
'''
from java.io import File
from java.lang import System
from org.python.util import JLineConsole, PythonInterpreter
from burp import IBurpExtender, IMenuItemHandler

from threading import Thread
import os
import re
import signal
import sys

from gds.burp import HttpRequest
from gds.burp.decorators import callback
from gds.burp.helpers import PluginMonitorThread
from gds.burp.menu import MenuItem, ConsoleMenu


class BurpExtender(IBurpExtender):
    def __init__(self):
        self.monitoring = []

    def __repr__(self):
        return '<BurpExtender %#x>' % (id(self),)


    def setCommandLineArgs(self, args):
        '''
        This method is invoked immediately after the implementation's
        constructor to pass any command-line arguments that were passed
        to Burp Suite on startup.

        The following command-line options have been made available:

        -i, --interactive   Run Burp in interactive mode (Jython Console)
        -f <FILE>           Restore from burp state file upon startup
        -h
        '''
        from optparse import OptionParser
        parser = OptionParser()

        parser.add_option('-i', '--interactive',
                          action='store_true',
                          help='Run Burp in interactive mode (Jython Console)')

        parser.add_option('-f', '--file', metavar='FILE',
                          help='Restore Burp state from FILE on startup')

        parser.add_option('-P', '--python-path',
                          default='',
                          help='Set PYTHONPATH used by Jython')

        parser.add_option('-d', '--debug', action='store_true')

        opt, args = parser.parse_args(list(args))

        if opt.interactive:
            from java.util import Properties

            pre_properties = System.getProperties()
            pre_properties['python.console'] = 'org.python.util.ReadlineConsole'

            post_properties = Properties()

            if opt.python_path:
                post_properties['python.path'] = opt.python_path

            PythonInterpreter.initialize(pre_properties, post_properties, sys.argv[1:])

            self.console = JLineConsole()
            self.console.exec('import __builtin__ as __builtins__')
            self.console.exec('from gds.burp import HttpRequest, HttpResponse')
            self.console.set('Burp', self)

            sys.stderr.write('Launching interactive session...\n')
            ConsoleThread(self.console).start()

        self.opt, self.args = opt, args

        return


    def applicationClosing(self):
        '''
        This method is invoked immediately before Burp Suite exits.
        '''
        return


    def registerExtenderCallbacks(self, callbacks):
        '''
        This method is invoked on startup.
        '''
        self._callbacks = callbacks

        if self.opt.file:
            if os.path.isfile(self.opt.file):
                self.restoreState(self.opt.file)
                self.issueAlert('restored state from %s' % (self.opt.file,))
            else:
                self.issueAlert('could not restore state from %s:'
                                'file does not exist' % (self.opt.file,))

        if self.opt.interactive:
            ConsoleMenu(_burp=self)

        if self.opt.debug:
            self.monitor = PluginMonitorThread(self)
            self.monitor.start()

        self.issueAlert('burp extender ready...')

        return


    def _check_cb(self):
        if hasattr(self, '_callbacks'):
            return getattr(self, '_callbacks')


    def _check_and_callback(self, method, *args):
        cb = self._check_cb()

        if not hasattr(cb, method.__name__):
            raise Exception("%s not available in your version of Burp" % (
                            method.__name__,))

        return getattr(cb, method.__name__)(*args)


    cb = property(_check_cb)


    @callback
    def makeHttpRequest(self, host, port, useHttps, request):
        return


    @callback
    def sendToRepeater(self, host, port, useHttps, request, tabCaption):
        return


    @callback
    def sendToIntruder(self, host, port, useHttps, request, *args):
        return


    @callback
    def sendToSpider(self, url):
        return


    @callback
    def doActiveScan(self, host, port, useHttps, request, *args):
        return


    @callback
    def doPassiveScan(self, host, port, useHttps, request, response):
        return


    @callback
    def getScanIssues(self, urlPrefix):
        return


    def registerMenuItem(self, menuItemCaption, menuItemHandler):
        '''
        This method can be used to register a new menu item which
        will appear on the various context menus that are used
        throughout Burp Suite to handle user-driven actions.

        :param menuItemCaption: The caption to be displayed on the
        menu item.
        :param menuItemHandler: The handler to be invoked when the
        user clicks on the menu item.
        '''
        _module = menuItemHandler.__module__
        _filename = sys.modules[_module].__file__
        _class = menuItemHandler.__class__.__name__

        self.monitoring.append({
            'filename': _filename.replace('$py.class', '.py'),
            'class': _class,
            'module': _module,
            'type': 'IMenuItemHandler',
            'instance': menuItemHandler,
            })

        self._check_and_callback(
            self.registerMenuItem, menuItemCaption, menuItemHandler)

        return


    def getProxyHistory(self, *args):
        '''
        This method returns a generator of all items in the proxy history.

        :params *args: Optional strings to match against url.
        '''
        if args:
            matchers = [re.compile(arg) for arg in args]
            for request in self._check_and_callback(self.getProxyHistory):
                for matcher in matchers:
                    if matcher.search(request.getUrl().toString()):
                        yield HttpRequest(request, _burp=self)
        else:
            for request in self._check_and_callback(self.getProxyHistory):
                yield HttpRequest(request, _burp=self)


    @callback
    def addToSiteMap(self, item):
        return


    def getSiteMap(self, *urlPrefixes):
        '''
        This method returns a generator of details of items in the site map.

        :params *urlPrefixes: Optional URL prefixes, in order to extract
        a specific subset of the site map. The method performs a simple
        case-sensitive text match, returning all site map items whose URL
        begins with the specified prefix. If this parameter is null,
        the entire site map is returned.
        '''
        for urlPrefix in urlPrefixes:
            for item in self._check_and_callback(self.getSiteMap, urlPrefix):
                yield HttpRequest(item, _burp=self)


    @callback
    def excludeFromScope(self, url):
        return


    @callback
    def includeInScope(self, url):
        return


    @callback
    def isInScope(self, url):
        return


    @callback
    def issueAlert(self, message):
        '''
        This method can be used to display a specified message in
        the Burp Suite alerts tab.

        :param message: The alert message to display.
        '''
        return


    def restoreState(self, filename):
        '''
        This method can be used to restore Burp's state from a
        specified saved state file.

        :param filename: The filename containing Burp's saved state.
        '''
        return self._check_and_callback(self.restoreState, File(filename))


    def saveState(self, filename):
        '''
        This method can be used to save Burp's state to a specified
        file. This method blocks until the save operation is completed,
        and must not be called from the event thread.

        :param filename: The filename to save Burp's state in.
        '''
        return self._check_and_callback(self.saveState, File(filename))


    @callback
    def loadConfig(self, config):
        '''
        This method causes Burp to load a new configuration from a
        dictionary of key/value pairs provided. Any settings not
        specified in the dict will be restored to their default values.
        To selectively update only some settings and leave the rest
        unchanged, you should first call saveConfig to obtain Burp's
        current configuration, modify the relevant items in the dict,
        and then call loadConfig with the same dict.

        :param config: A dict of key/value pairs to use as Burp's new
        configuration.
        '''
        return


    def saveConfig(self):
        '''
        This method causes Burp to return its current configuration
        as a dictionary of key/value pairs.
        '''
        return dict(self._check_and_callback(self.saveConfig))


    @callback
    def setProxyInterceptionEnabled(self, enabled):
        '''
        This method sets the interception mode for Burp Proxy.

        :param enabled: Indicates whether interception of proxy messages
        should be enabled.
        '''
        return


    def getBurpVersion(self):
        '''
        This method retrieves information about the version of Burp
        in which the extension is running. It can be used by extensions
        to dynamically adjust their behavior depending on the
        functionality and APIs supported by the current version.
        '''
        return list(self._check_and_callback(self.getBurpVersion))


    @callback
    def exitSuite(self, promptUser):
        '''
        This method can be used to shut down Burp programmatically,
        with an optional prompt to the user. If the method returns,
        the user cancelled the shutdown prompt.

        :param promptUser: Indicates whether to prompt the user to
        confirm the shutdown.
        '''
        return


class ConsoleThread(Thread):
    def __init__(self, console):
        Thread.__init__(self, name='jython-console')
        self.console = console

    def run(self):
        while True:
            try:
                self.console.interact()
            except Exception:
                pass


def _sigbreak(signum, frame):
    '''
    Don't do anything upon receiving ^C. Require user to actually exit
    via Burp, preventing them from accidentally killing Burp from the
    interactive console.
    '''
    pass

signal.signal(signal.SIGINT, _sigbreak)
