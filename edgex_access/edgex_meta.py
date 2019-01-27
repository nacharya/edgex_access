''' only access the metadata location functions '''

import os
import hashlib

from datetime import datetime
from sqlitedict import SqliteDict
from .edgex_exceptions import *

# buffer hash computation
class EdgexHash:
    """ Calculate the hash for the buffer, file
        and pick up which hash algorithm to use
    """
    def __init__(self):
        pass

    @classmethod
    def signature(cls, file_name):
        """ Given a file calculate the signature """
        hash_sha256 = hashlib.sha256()
        file_des = open(file_name, 'rb')
        chunk = file_des.read()
        hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    @classmethod
    def md5(cls, databuf):
        """ Calculate the MD5 hash """
        hash_md5 = hashlib.md5()
        hash_md5.update(databuf)
        return hash_md5.hexdigest()

    @classmethod
    def sha256(cls, databuf):
        """ Calculate the SHA256 hash """
        hash_sha256 = hashlib.sha256()
        hash_sha256.update(databuf)
        return hash_sha256.hexdigest()


class EdgexMetaSQLite:
    """ Only store the meta data for the data """
    def __init__(self, cfg, vdb_file=None):
        """ COnstructor for the meta data store """
        self.path = cfg.get_meta_location()
        if vdb_file is None:
            vdb_file = "edgex_meta.db"
        self.mname = self.path + "/" + vdb_file

    def show(self):
        """ print out the metadata as it is -- debugging """
        metadict = SqliteDict(self.mname, autocommit=True)
        for key, value in metadict.items():
            print(key, value)
        metadict.close()
    def init(self):
        """ Initialize """
        metadict = SqliteDict(self.mname, autocommit=True)
        key = "edgex_meta"
        tm_now = datetime.utcnow()
        val = tm_now.strftime('%Y%m%dT%H%M%SZ')
        metadict[key] = val
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
