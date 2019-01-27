''' Base classes use by higher level '''

from .edgex_exceptions import *

class EdgexStoreBase:
    """ Base class for Store definition """
    def __init__(self, cfg):
        self.name = cfg['NAME']
        self.type = cfg['STORE_TYPE']
        self.bucket = cfg['BUCKET']
        self.token = cfg['TOKEN']
        #if (self.type != "FS") or (self.type != "S3"):
        #    raise InvalidStore(self.type)
        self.tag = cfg['TAG']
        #if not self.tag:
            #raise EmptyTag(self.tag)

    def islocal(self):
        """ is this a local filesystem """
        return self.type == "FS"
    def get_tag(self):
        """ tag is the short name we use """
        return self.tag
    def set_tag(self, avalue):
        """ set tag value """
        self.tag = avalue
    def get_name(self):
        """ Get the name """
        return self.name
    def get_type(self):
        """ Get the type """
        return self.type
    def default_bucket(self):
        """ Get the named default bucket """
        return self.bucket

class EdgexMetaBase:
    """ Base class to access the metadata only """
    def __init__(self):
        self.store_file = ""
    def init_store(self, store_file):
        """ Initialize the meta store if needed """
        self.store_file = store_file
    def clear_store(self):
        """ remove and delete the meta store """
        pass

class EdgexAccessBase:
    """ Base class to access the I/O type. FS, S3 ,In-Mem etc """
    def __init__(self, obj, atype):
        self.obj = obj
        self.type = atype
    def get_type(self):
        """ if this is S3, FS, MEM """
        return self.type
    def get_obj(self):
        """ return the obj code """
        return self.obj
