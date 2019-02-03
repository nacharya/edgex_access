''' place objects in out of only memory '''

from .edgex_exceptions import *
from .edgex_base import EdgexStoreBase, EdgexAccessBase



class EdgexMemStore(EdgexStoreBase):
    """ store stuff in memory for small things """
    def __init__(self, cfg):
        super().__init__(cfg)
        self.bucketname = cfg['BUCKET']
        self.endpoint = cfg['ENDPOINT']
    def get_bucketname(self):
        """ the mem space is denoted by a bucket name """
        return self.bucketname
    def get_endpoint(self):
        """ get the endpoint """
        return self.endpoint

class EdgexMemAccess(EdgexAccessBase):
    """ In-memory access """
    def __init__(self, obj):
        super().__init__(obj, "MEM")

    async def list(self, session=None):
        """ List the element in-memory """
        pass
    async def put(self, session=None):
        """ put the databuf of the object in-memory """
        pass
    async def get(self, session=None):
        """ get the databuf from in-memory """
        if not self.obj.databuf:
            raise InvalidDataBuffer(self.obj.pathname())
        return self.obj.databuf
    async def delete(self, session=None):
        """ delete the entry from in-memory """
        if not self.obj.databuf:
            raise InvalidDataBuffer(self.obj.pathname())
        self.obj.databuf = ""
    async def exists(self, session=None):
        """ check of this exists in-memory """
        pass
    async def info(self, session=None):
        """ return the meta info on this """
        pass
