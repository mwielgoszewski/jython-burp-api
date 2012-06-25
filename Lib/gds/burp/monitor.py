# -*- coding: utf-8 -*-
from java.io import File

from threading import Thread
import time
import types
import weakref


class PluginMonitorThread(Thread):
    def __init__(self, _burp, interval=5):
        Thread.__init__(self, name='plugin-monitor')
        self.burp = self._burp = _burp
        self.log = self.burp.log
        self.interval = interval

        for plugin in self._burp.monitoring:
            self.burp.issueAlert('Monitoring %s' % (plugin.get('class'),))
            self.log.debug('Monitoring %s', plugin.get('class'))
            self._monitor_plugin(plugin)

    def _has_changed(self, plugin):
        lastModified = File(plugin.get('filename')).lastModified()

        if plugin.get('modified', -1) < lastModified:
            plugin['modified'] = lastModified
            return True
        else:
            return False

    def _monitor_plugin(self, plugin):
        if self._has_changed(plugin):
            if plugin.get('reloaded', False):
                self.log.info('Reloading %s', plugin.get('class'))
            self._reload(plugin)

        return

    def _reload(self, plugin):
        instance = plugin.get('instance')

        if instance() is None:
            self.log.warn('Reference to object %s.%s no longer exists',
                plugin.get('module'), plugin.get('class'))
            return

        m = __import__(plugin.get('module'), globals(), locals(),
                       [plugin.get('class')])
        reload(m)

        klass = getattr(m, plugin.get('class'))

        if plugin.get('type') == 'IMenuItemHandler':
            self._patch_menu_item(instance(), klass)
        else:
            #TODO copy over old instance__dict__ to new instance
            instance = weakref.ref(klass(self._burp))

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
                for plugin in self._burp.monitoring:
                    self._monitor_plugin(plugin)
            except Exception:
                self.log.exception('Error reloading...: %s', plugin)

            time.sleep(self.interval)
