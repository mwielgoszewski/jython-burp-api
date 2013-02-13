# -*- coding: utf-8 -*-
'''
gds.burp.ui
~~~~~~~~~~~

This module provides UI capabilities to the jython-burp-api.
'''
from javax.swing import JScrollPane

from burp import ITab

from .console import Console
import gds.burp.settings as settings


class ConsoleTab(ITab):

    def __init__(self, burp):
        self.burp = burp
        self.log = burp.log
        self.config = burp.config

        self.caption = burp.loadExtensionSetting(*settings.CONSOLE_CAPTION)
        self.scrollpane = JScrollPane()

        self.console = Console(burp)
        self.scrollpane.setViewportView(self.console.textpane)
        
        self.burp.addSuiteTab(self)
        self.burp.customizeUiComponent(self.getUiComponent())

    def getUiComponent(self):
        return self.scrollpane

    def getTabCaption(self):
        return self.caption

    @property
    def interpreter(self):
        return self.console.interp
