# -*- coding: utf-8 -*-
from .api import INewScanIssueHandler
from .core import Component, ExtensionPoint


class NewScanIssueDispatcher(Component):

    dispatchers = ExtensionPoint(INewScanIssueHandler)

    def newScanIssue(self, issue):
        for dispatch in self.dispatchers:
            dispatch.newScanIssue(issue)
