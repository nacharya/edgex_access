''' Filesystem specific access '''

import os
import aiofiles

from logzero import logger
from .edgex_base import EdgexStoreBase, EdgexAccessBase
from .edgex_base import EdgexStoreBase, EdgexAccessBase
from .edgex_exceptions import *

MAX_SINGLE_OBJ = 5* 1024 * 1024 * 1024 # 5Gb

class EdgexFSStore(EdgexStoreBase):
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
    def change_value(self, key, value):
        """ change config value """
        if key.upper() == "TAG":
            super().set_tag(value)

class EdgexFSAccess(EdgexAccessBase):
    ''' functions for filesystem access '''
    def __init__(self, obj):
        super().__init__(obj, "FS")

    async def list(self, session=None):
        ''' object listing or directory listing '''
        final_list = []
        if self.obj.isfolder():
            final_list = os.listdir(self.obj.pathname())
            print(final_list)
            i = 0
            for f_l in final_list:
                if os.path.isdir(self.obj.pathname() + "/" + f_l):
                    final_list[i] = f_l + "/"
                i += 1
        else:
            if os.path.isfile(self.obj.pathname()):
                final_list.append(self.obj.pathname())
        return final_list

    async def put(self, session=None):
        ''' write out an object '''
        isdbuf = (self.obj.databuf is not None)

        logger.info(str("put " + self.obj.pathname() + " databuf " + str(isdbuf)))

        if not isdbuf:
            try:
                os.makedirs(os.path.dirname(self.obj.pathname()))
            except Exception as exp:
                logger.exception(exp)
                raise exp
            logger.error(str("No data buffer for " + self.obj.pathname()))
            return self.obj.pathname()
        if not os.path.exists(os.path.dirname(self.obj.pathname())):
            try:
                os.makedirs(os.path.dirname(self.obj.pathname()))
            except Exception as exp:
                logger.exception(exp)
                raise exp
        async with aiofiles.open(self.obj.pathname(), mode='wb') as f_l:
            await f_l.write(self.obj.databuf)
            await f_l.flush()
        return self.obj.pathname()

    async def get(self, session=None):
        ''' read an object '''
        file_size = os.stat(self.obj.pathname()).st_size
        if file_size > MAX_SINGLE_OBJ:
            raise EntityTooLarge(str(file_size))
        async with aiofiles.open(self.obj.pathname(), mode='rb') as f_l:
            file_data = await f_l.read()
        f_l.close()
        return file_data

    async def delete(self, session=None):
        ''' delete an object '''
        if os.path.isfile(self.obj.pathname()):
            os.remove(self.obj.pathname())
            return True
        if os.path.isdir(self.obj.pathname()):
            dentries = os.listdir(self.obj.pathname())
            if not dentries:
                os.rmdir(self.obj.pathname())

    async def exists(self, session=None):
        ''' check of the file exists '''
        return self.obj.stat()

    async def info(self, session=None):
        ''' meta info on the object if any '''
        if self.obj.stat() is True:
            metadata = {self.obj.pathname():os.stat(self.obj.pathname())}
            return metadata
        return None
