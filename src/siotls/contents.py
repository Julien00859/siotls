content_registry = {}

class Content:
    content_type: ContentType

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Content in cls.__bases__:
            content_registry[cls.content_type] = cls


class ApplicationData(Content, Serializable):
    content_type = ContentType.APPLICATION_DATA
    data: bytes

    def __init__(self, data):
        self.data = data

    @classmethod
    def parse(cls, data):
        return cls(data)

    def serialize(self):
        return self.data
