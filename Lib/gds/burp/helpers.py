from java.io import File

from threading import Thread
import time
import types

from .menu import MenuItem


class PluginMonitorThread(Thread):
    def __init__(self, _burp, interval=5):
        Thread.__init__(self, name='plugin-monitor')
        self._burp = _burp
        self.interval = interval
        self.hashes = {}

        for plugin in self._burp.monitoring:
            self._burp.issueAlert('monitoring %s' % (plugin.get('class'),))

    def _has_changed(self, filename):
        filename = filename.replace('$py.class', '.py')
        lastModified = File(filename).lastModified()

        if self.hashes.get(filename, -1) < lastModified:
            self.hashes.update({filename: lastModified})
            return True
        else:
            return False

    def _monitor_plugin(self, plugin):
        if self._has_changed(plugin.get('filename')):
            self._burp.issueAlert('Reloading %s' % (plugin.get('class'),))

            instance = plugin.get('instance')

            m = __import__(instance.__module__, globals(), locals(),
                           [plugin.get('class')])
            reload(m)

            klass = getattr(m, plugin.get('class'))

            if isinstance(instance, MenuItem):
                # hot patch that bitch
                menuItemClicked = getattr(klass, 'menuItemClicked')
                instance.menuItemClicked = types.MethodType(
                        menuItemClicked, instance, klass)
            else:
                instance = klass(self._burp)

    def run(self):
        while True:
            try:
                for plugin in self._burp.monitoring:
                    self._monitor_plugin(plugin)
            except Exception, e:
                self._burp.issueAlert('Error reloading...: %s' % (e,))

            time.sleep(self.interval)
