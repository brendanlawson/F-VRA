class FVRAError(Exception):
    pass

class IndexNotFound(FVRAError):
    pass

class CVENotLocalized(FVRAError):
    pass

class GraphConnectionError(FVRAError):
    pass
