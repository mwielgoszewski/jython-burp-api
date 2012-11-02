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
import inspect
import logging
import os
import re
import signal
import site
import sys
import weakref

from gds.burp import HttpRequest
from gds.burp.config import Configuration, ConfigSection
from gds.burp.core import Component, ComponentManager
from gds.burp.decorators import callback
from gds.burp.dispatchers import NewScanIssueDispatcher, PluginDispatcher
from gds.burp.monitor import PluginMonitorThread


logging._srcfile = None
logging.logThreads = 0
logging.logProcesses = 0


class BurpExtender(IBurpExtender, ComponentManager):

    _components = ConfigSection('components', '')
    _menus = ConfigSection('menus', '')

    def __init__(self):
        ComponentManager.__init__(self)
        self.log = logging.getLogger(self.__class__.__name__)
        self.monitoring = {}

    def __repr__(self):
        return '<BurpExtender at %#x>' % (id(self),)

    def _monitor_item(self, obj):
        # don't monitor objects initialized in the interpreter

        if obj.__module__ == '__main__':
            return

        mod = obj.__module__
        cls = obj.__class__.__name__

        # Monitor the actual configuration file rather than the
        # module the Configuration class is defined in

        if isinstance(obj, Configuration):
            filename = obj.filename

        elif isinstance(obj, (Component, IMenuItemHandler)):
            filename = inspect.getsourcefile(obj.__class__)

        elif isinstance(obj, type):
            filename = inspect.getsourcefile(obj)

        monitoring = self.monitoring.setdefault(filename, [])

        monitoring.append({
            'class': cls,
            'instance': weakref.ref(obj),
            'module': mod,
            })

        return

    def componentActivated(self, component):
        self.log.debug('Activating component: %r', component)
        component.burp = self
        component.config = self.config
        component.log = self.log

        return

    def setCommandLineArgs(self, args):
        '''
        This method is invoked immediately after the implementation's
        constructor to pass any command-line arguments that were passed
        to Burp Suite on startup.

        The following command-line options have been made available:

        -i, --interactive   Run Burp in interactive mode (Jython Console)
        -f <FILE>           Restore from burp state file upon startup
        -d, --debug         Set log level to DEBUG
        -v, --verbose       Set log level to INFO
        -C, --config        Specify an alternate config (default: burp.ini)
        --disable-reloading Disable monitoring of plugins for changes
        -h
        '''
        from optparse import OptionParser
        parser = OptionParser()

        parser.add_option('-i', '--interactive',
                          action='store_true',
                          help='Run Burp in interactive mode (Jython Console)')

        parser.add_option('-f', '--file', metavar='FILE',
                          help='Restore Burp state from FILE on startup')

        parser.add_option('-d', '--debug',
                          action='store_true',
                          help='Set log level to DEBUG')

        parser.add_option('-v', '--verbose',
                          action='store_true',
                          help='Set log level to INFO')

        parser.add_option('-P', '--python-path',
                          default='',
                          help='Set PYTHONPATH used by Jython')

        parser.add_option('-C', '--config',
                          default='burp.ini',
                          help='Specify alternate jython-burp config file')

        parser.add_option('--disable-reloading',
                          action='store_true',
                          help='Disable hot-reloading when a file is changed')

        opt, args = parser.parse_args(list(args))

        if opt.debug:
            logging.basicConfig(
                filename='jython-burp.log',
                format='%(asctime)-15s - %(levelname)s - %(message)s',
                level=logging.DEBUG)

        elif opt.verbose:
            logging.basicConfig(
                filename='jython-burp.log',
                format='%(asctime)-15s - %(levelname)s - %(message)s',
                level=logging.INFO)

        self.config = Configuration(os.path.abspath(opt.config))

        if opt.interactive:
            from java.util import Properties

            pre_properties = System.getProperties()
            pre_properties['python.console'] = 'org.python.util.ReadlineConsole'

            post_properties = Properties()

            if opt.python_path:
                post_properties['python.path'] = opt.python_path

            PythonInterpreter.initialize(
                pre_properties, post_properties, sys.argv[1:])

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
        self.log.debug('Shutting down Burp')
        return

    def registerExtenderCallbacks(self, callbacks):
        '''
        This method is invoked on startup.
        '''
        self._callbacks = callbacks

        if self.opt.file:
            if os.path.isfile(self.opt.file):
                self.restoreState(self.opt.file)
                self.issueAlert('Restored state from %s' % (self.opt.file,))
            else:
                self.issueAlert('Could not restore state from %s:'
                                'file does not exist' % (self.opt.file,))

        for module, _ in self._menus.options():
            if self._menus.getbool(module) is True:
                for menu in _get_menus(module):
                    menu(self)

        for component, _ in self._components.options():
            if self._components.getbool(component) is True:
                _get_plugins(component)

        if not self.opt.disable_reloading:
            self._monitor_item(self.config)
            self.monitor = PluginMonitorThread(self)
            self.monitor.start()

        self.issueAlert('Burp extender ready...')

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
        self._monitor_item(menuItemHandler)

        self._check_and_callback(
            self.registerMenuItem, menuItemCaption, menuItemHandler)

        return


    def newScanIssue(self, issue):
        '''
        This method is invoked whenever Burp Scanner discovers a new,
        unique issue, and can be used to perform customised reporting
        or logging of issues.

        Plugins should implement the :meth:`~INewScanIssueHandler.newScanIssue`
        method of the :class:`INewScanIssueHandler` interface to act upon
        new scan issues as they are identified.

        :param issue: Details of the new scan issue.
        '''
        return NewScanIssueDispatcher(self).newScanIssue(issue)


    def processHttpMessage(self, toolName, messageIsRequest, messageInfo):
        '''
        This method is invoked whenever any of Burp's tools makes an HTTP
        request or receives a response. It allows extensions to intercept
        and modify the HTTP traffic of all Burp tools. For each request,
        the method is invoked after the request has been fully processed
        by the invoking tool and is about to be made on the network. For
        each response, the method is invoked after the response has been
        received from the network and before any processing is performed
        by the invoking tool.

        Plugins should implement the :meth:`processRequest` and/or
        :meth:`processResponse` methods of one or more interfaces in
        :module:`gds.burp.api`.

        A plugin may implement more than one interface, and implement both
        `processRequest` and `processResponse` methods. This allows plugins
        to only hook certain tools in specific scenarios, such as "only
        hook requests sent via Intruder or Scanner, and only hook responses
        received via Proxy tool.

        An example is provided below that only modifies requests as they
        are made via Repeater and Intruder.

        .. code-block:: python
            class MyPlugin(Component):

                implements(IIntruderRequestHandler, IRepeaterRequestHandler)

                def processRequest(self, request):
                    # replace all occurrences of 'somestring' in HTTP
                    # request with 'anotherstring'.
                    request.raw = request.raw.replace('somestring',
                                                      'anotherstring')

        '''
        return PluginDispatcher(self).processHttpMessage(
            toolName, messageIsRequest, messageInfo)


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
                        break
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
        for urlPrefix in urlPrefixes or ('http',):
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

    def exitSuite(self, promptUser=False):
        '''
        This method can be used to shut down Burp programmatically,
        with an optional prompt to the user. If the method returns,
        the user cancelled the shutdown prompt.

        :param promptUser: Indicates whether to prompt the user to
        confirm the shutdown (default is False: no prompt).
        '''
        if promptUser is True:
            return self._check_and_callback(self.exitSuite, True)

        return self._check_and_callback(self.exitSuite, False)


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


def _get_menus(menu_module):
    module = menu_module.split('.')
    klass = module.pop()

    try:
        m = __import__('.'.join(module), globals(), locals(), module[-1])
    except ImportError:
        logging.error('Could not import module %s', '.'.join(module))
        return []

    if klass == '*':
        menus = []

        for name, obj in inspect.getmembers(m):
            if name == 'MenuItem':
                continue

            if inspect.isclass(obj) and IMenuItemHandler in inspect.getmro(obj):
                menus.append(obj)

        return menus

    try:
        return [getattr(m, klass)]
    except AttributeError:
        logging.error('Could not import %s from module %s',
                      klass, '.'.join(module))

        return []


def _get_plugins(plugin_module):
    module = plugin_module.split('.')
    klass = module.pop()

    if klass == '*':
        to_import = module[-1:]
    else:
        to_import = [klass]

    try:
        __import__('.'.join(module), globals(), locals(), to_import)
    except ImportError:
        logging.error('Could not import %s from module %s',
                      ', '.join(to_import), '.'.join(module))

    return


def _sigbreak(signum, frame):
    '''
    Don't do anything upon receiving ^C. Require user to actually exit
    via Burp, preventing them from accidentally killing Burp from the
    interactive console.
    '''
    pass

signal.signal(signal.SIGINT, _sigbreak)
