# -*- coding: utf-8 -*-
from .api import IScanIssueHandler
from .core import Component, ExtensionPoint


class NewScanIssueDispatcher(Component):

    dispatchers = ExtensionPoint(IScanIssueHandler)

    def newScanIssue(self, issue):
        for dispatch in self.dispatchers:
            dispatch.newScanIssue(issue)
