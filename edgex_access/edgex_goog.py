''' Google Storage specific using google APIs '''

import os
from .edgex_base import EdgexStoreBase, EdgexAccessBase

class EdgexGoogStore(EdgexStoreBase):
    """ Stuff needed to access the local filesystem
    """
    def __init__(self, cfg):
        super().__init__(cfg)
        self.cwd = os.getcwd()
    def basename(self):
        """ Get the basename """
        return os.path.basename(self.cwd)
    def get_endpoint(self):
        """ Get the endpoint """
        return self.basename()


class EdgexGoogAccess(EdgexAccessBase):
    ''' Google specific storage API access '''
    pass
