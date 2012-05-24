import types


class callback(object):
    def __init__(self, f, *args, **kwargs):
        self.f = f
        if hasattr(f, "__call__"):
            name = self.f.__name__
        else:
            # f is a class or static method
            tmp = f.__get__(None, f.__class__)
            name = tmp.__name__
        #print("Tracing: {0}".format(name))

    def __call__(self, *args, **kwargs):
        #print("Calling: {0}".format(self.f.__name__))
        return self.f(*args, **kwargs)

    def __get__(self, obj, ownerClass=None):
        if obj is None:
            f = self.f
            if not hasattr(f, "__call__"):
                self.f = f.__get__(None, ownerClass)
            return self
        else:
            return types.MethodType(obj._check_and_callback, self.f, ownerClass)

