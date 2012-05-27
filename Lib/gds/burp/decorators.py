# -*- coding: utf-8 -*-
'''
gds.burp.decorators
~~~~~~~~~~~~~~~~~~~

This module contains decorators used by BurpExtender.
'''
import types


class callback(object):
    '''
    Decorator to exposes IBurpExtenderCallbacks to BurpExtender class
    methods with the same name, reducing a lot of repetive code.
    '''
    def __init__(self, func, *args, **kwargs):
        self.func = func
        if hasattr(func, "__call__"):
            name = self.func.__name__
        else:
            # func is a class or static method
            tmp = func.__get__(None, func.__class__)
            name = tmp.__name__
        #print("Tracing: {0}".format(name))

    def __call__(self, *args, **kwargs):
        #print("Calling: {0}".format(self.func.__name__))
        return self.func(*args, **kwargs)

    def __get__(self, obj, parent=None):
        if obj is None:
            func = self.func
            if not hasattr(func, "__call__"):
                self.func = func.__get__(None, parent)
            return self
        else:
            return types.MethodType(obj._check_and_callback, self.func, parent)

