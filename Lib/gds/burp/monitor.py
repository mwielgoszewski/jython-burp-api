from java.io import File

from threading import Thread
import time
import types
import weakref


class PluginMonitorThread(Thread):
    def __init__(self, _burp, interval=5):
        Thread.__init__(self, name='plugin-monitor')
        self._burp = _burp
        self.interval = interval
        self.hashes = {}

        for plugin in self._burp.monitoring:
            self._burp.issueAlert('monitoring %s' % (plugin.get('class'),))
            self._monitor_plugin(plugin)

    def _has_changed(self, filename):
        lastModified = File(filename).lastModified()

        if self.hashes.get(filename, -1) < lastModified:
            self.hashes.update({filename: lastModified})
            return True
        else:
            return False

    def _monitor_plugin(self, plugin):
        if self._has_changed(plugin.get('filename')):
            if plugin.get('reloaded', False):
                self._burp.issueAlert('reloading %s' % (plugin.get('class'),))
            self._reload(plugin)

        return

    def _reload(self, plugin):
        instance = plugin.get('instance')

        if instance() is None:
            self._burp.issueAlert('reference to object %s.%s no longer '
                'exists' % (plugin.get('module'), plugin.get('class'),))
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
        reloaded one. This requires annotating the 'menuItemClicked'
        class method with the @staticmethod decorator.
        '''
        menuItemClicked = getattr(menu_class, 'menuItemClicked')

        instance.menuItemClicked = types.MethodType(
                menuItemClicked, instance, menu_class)

        return

    def run(self):
        while True:
            try:
                for plugin in self._burp.monitoring:
                    self._monitor_plugin(plugin)
            except Exception, e:
                self._burp.issueAlert('Error reloading...: %s' % (e,))

            time.sleep(self.interval)
