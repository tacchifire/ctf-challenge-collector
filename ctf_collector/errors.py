class CollectorError(Exception):
    def __init__(self, code, message, *, status=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class PartialCollectionError(CollectorError):
    pass
