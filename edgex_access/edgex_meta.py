''' only access the metadata location functions '''

import os

from sqlitedict import SqliteDict
from .edgex_exceptions import *
from .edgex_access import EdgexHash

class EdgexMeta:
    """ Only store the meta data for the data """
    def __init__(self, cfg, vdb_file=None, store=None):
        self.path = cfg.get_meta_location()
        if (store is None) and (vdb_file is None):
            raise InvalidStore(str(vdb_file))
        if vdb_file is None:
            self.mname = self.path + "/" + store.get_name()
        elif store is None:
            self.mname = self.path + "/" + vdb_file

    def show(self):
        """ print out the metadata as it is -- debugging """
        metadict = SqliteDict(self.mname, autocommit=True)
        for key, value in metadict.items():
            print(key, value)
        metadict.close()

    def put(self, object_path, databuf):
        """ create and put a meta entry for this object """
        hash_sha256 = EdgexHash()
        key = hash_sha256.sha256(databuf)
        val = object_path
        metadict = SqliteDict(self.mname, autocommit=True)
        metadict[key] = val
        metadict.close()

    def get(self, key):
        """ get the meta entry with this key """
        metadict = SqliteDict(self.mname, autocommit=True)
        retval = metadict[key]
        metadict.close()
        return retval

    def delete(self, key):
        """ delete this meta entry """
        metadict = SqliteDict(self.mname, autocommit=True)
        del metadict[key]
        metadict.commit()
        metadict.close()

    def deldb(self):
        """ wipe out the meta db """
        if os.path.isfile(self.mname) is True:
            os.unlink(self.mname)
