# -*- coding: utf-8 -*-
from .core import Interface

class INewScanIssueHandler(Interface):
    '''
    Extension point interface for components to perform actions
    whenever Burp Scanner discovers a new, unique issue.
    '''

    def newScanIssue(issue):
        '''
        This method is invoked whenever Burp Scanner discovers a new,
        unique issue, and can be used to perform customised reporting
        or logging of issues.
        '''
