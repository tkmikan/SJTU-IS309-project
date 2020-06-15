from utils import *


class WUP:
    components = ['IMEI', 'MAC', 'IP', 'QQ', 'version']

    def __init__(self, **kwargs):
        if any(c not in kwargs for c in self.components):
            raise ValueError('WUP component missing')
        for c in self.components:
            setattr(self, c, kwargs.get(c))

    def __repr__(self):
        s = ', '.join(f'{c}: {repr(getattr(self, c))}' for c in self.components if getattr(self, c) is not None)
        return f'<WUP {s}>'

    def dumps(self):
        return marshal.dumps({k: v for k, v in self.__dict__.items() if v is not None})

    @classmethod
    def loads(cls, data):
        return cls(**marshal.loads(data))
