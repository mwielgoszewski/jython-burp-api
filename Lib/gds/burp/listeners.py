# -*- coding: utf-8 -*-
'''
gds.burp.listeners
~~~~~~~~~~~~~~~~~~

Listeners that implement new Burp Extender API's.
'''
from burp import IExtensionStateListener, IHttpListener, IScannerListener

from .dispatchers import NewScanIssueDispatcher, PluginDispatcher

import gds.burp.settings as settings

__all__ = [
    'PluginListener',
    'ScannerListener',
    'SaveConfigurationOnUnload',
    ]


class SaveConfigurationOnUnload(IExtensionStateListener):
    def __init__(self, burp):
        self.burp = burp
        self.log = burp.log

    def saveExtensionSetting(self, name, value):
        try:
            self.log.debug('Saving extension setting %s: %r', name, value)
            self.burp.saveExtensionSetting(name, value)
        except Exception:
            self.log.exception('Error saving extension setting %s: %r',
                               name, value)

    def extensionUnloaded(self):
        self.saveExtensionSetting(settings.CONFIG_FILENAME[0],
                                  self.burp.config.filename)

        self.saveExtensionSetting(settings.LOG_LEVEL[0],
                                  self.burp.log.getEffectiveLevel())

        self.saveExtensionSetting(settings.LOG_FILENAME[0],
                                  self.burp._handler.baseFilename)

        self.saveExtensionSetting(settings.LOG_FORMAT[0],
                                  self.burp._handler.formatter._fmt)

        self.burp.issueAlert('Burp extender unloaded...')
        self.log.debug('Shutting down Burp')
        return


class PluginListener(IHttpListener):
    def __init__(self, burp):
        self.burp = burp

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        toolName = self.burp.getToolName(toolFlag)

        return PluginDispatcher(self.burp).processHttpMessage(
            toolName, messageIsRequest, messageInfo)


class ScannerListener(IScannerListener):
    def __init__(self, burp):
        self.burp = burp

    def newScanIssue(self, issue):
        return NewScanIssueDispatcher(self.burp).newScanIssue(issue)
