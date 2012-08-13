# -*- coding: utf-8 -*-
from threading import Thread
from types import MethodType
import os.path
import sys
import time


class PluginMonitorThread(Thread):
    def __init__(self, burp, interval=5):
        Thread.__init__(self, name='plugin-monitor')
        self.burp = burp
        self.log = self.burp.log
        self.interval = interval
        self.mtimes = {}

        for filename in self.burp.monitoring:
            self.log.debug('Monitoring %s for changes', filename)

            self.mtimes[filename] = os.path.getmtime(filename)

            for plugin in self.burp.monitoring.get(filename, []):
                self.burp.issueAlert('Monitoring %s' % (plugin.get('class'),))

    def __has_changed(self, filename):
        lastModified = os.path.getmtime(filename)

        if lastModified > self.mtimes.get(filename, -1):
            self.mtimes[filename] = lastModified
            return True
        else:
            return False

    def __monitor(self, filename, plugins):
        if self.__has_changed(filename):
            self.log.info('%s has been modified since it was first imported!',
                          filename)

            for plugin in plugins:
                self.log.debug('Reloading %s', plugin.get('class'))
                self.__reload(plugin)

        return

    def __reload(self, plugin):
        from burp import IMenuItemHandler
        from gds.burp.config import Configuration

        instance = plugin.get('instance')

        if instance() is None:
            self.log.warn('Reference to object %s.%s no longer exists',
                plugin.get('module'), plugin.get('class'))

            return

        if isinstance(instance(), IMenuItemHandler):
            module = sys.modules[plugin.get('module')]

            reload(module)

            klass = getattr(module, plugin.get('class'))
            self._patch_menu_item(instance(), klass)

        elif isinstance(instance(), Configuration):
            instance().parse_if_needed(force=True)

        return

    def _patch_menu_item(self, instance, new_cls):
        '''
        Because Burp does not expose anyway to un-register an
        IMenuItemHandler, we need to get hold of the current instance
        and monkey patch the 'menuItemClicked' method with the newly
        reloaded one.
        '''
        menuItemClicked = new_cls.menuItemClicked.im_func
        setattr(instance, 'menuItemClicked',
                MethodType(menuItemClicked, instance, instance.__class__))

        return

    def run(self):
        while True:
            try:
                for filename, plugins in self.burp.monitoring.iteritems():
                    self.__monitor(filename, plugins)
            except Exception:
                self.log.exception('Error reloading...: %s', filename)

            time.sleep(self.interval)
