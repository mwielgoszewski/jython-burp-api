# -*- coding: utf-8 -*-
from threading import Thread
import os.path
import time
import types


class PluginMonitorThread(Thread):
    def __init__(self, burp, interval=5):
        Thread.__init__(self, name='plugin-monitor')
        self.burp = burp
        self.log = self.burp.log
        self.interval = interval

        for plugin in self.burp.monitoring:
            self.burp.issueAlert('Monitoring %s' % (plugin.get('class'),))
            self.log.debug('Monitoring %s', plugin.get('class'))
            self.__monitor(plugin)

    def __has_changed(self, plugin):
        srcfile = plugin.get('filename')
        lastModified = os.path.getmtime(srcfile)

        if lastModified > plugin.get('modified', -1):
            plugin['modified'] = lastModified
            return True
        else:
            return False

    def __monitor(self, plugin):
        if self.__has_changed(plugin):
            if plugin.get('reloaded', False):
                self.log.info('Reloading %s', plugin.get('class'))
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
            mod = __import__(plugin.get('module'), globals(), locals(),
                           [plugin.get('class')])
            reload(mod)

            klass = getattr(mod, plugin.get('class'))
            self._patch_menu_item(instance(), klass)

        elif isinstance(instance(), Configuration):
            instance().parse_if_needed(force=True)

        plugin['reloaded'] = True

        return

    def _patch_menu_item(self, instance, menu_class):
        '''
        Because Burp does not expose anyway to un-register an
        IMenuItemHandler, we need to get hold of the current instance
        and monkey patch the 'menuItemClicked' method with the newly
        reloaded one.
        '''
        menuItemClicked = getattr(menu_class, 'menuItemClicked')
        types.MethodType(menuItemClicked, instance, menu_class)

        return

    def run(self):
        while True:
            try:
                for plugin in self.burp.monitoring:
                    self.__monitor(plugin)
            except Exception:
                self.log.exception('Error reloading...: %s', plugin)

            time.sleep(self.interval)
