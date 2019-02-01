""" The main edgex_access file that has all the classes used in this
    module.
"""

from datetime import datetime
import os
import json
import random

import asyncio
import aiobotocore
import time

from logzero import logger

from .edgex_exceptions import *
from .edgex_base import *
from .edgex_fs import *
from .edgex_s3 import *
from .edgex_mem import *
from .edgex_meta import *
from .edgex_goog import *

# import requests-aws4auth

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


class EdgexStore:
    """ Specific description of each store """

    def __init__(self, cfg):
        if cfg['STORE_TYPE'] == "S3":
            self.store = EdgexS3Store(cfg)
        elif cfg['STORE_TYPE'] == "FS":
            self.store = EdgexFSStore(cfg)
        elif cfg['STORE_TYPE'] == "MEM":
            self.store = EdgexMemStore(cfg)
        else:
            raise InvalidStore(cfg['STORE_TYPE'])

    def islocal(self):
        """ return if this is a local store """
        return self.store.islocal()

    def get_access(self):
        """ return the access key """
        return self.store.get_access()

    def get_secret(self):
        """ return the secret key """
        return self.store.get_secret()

    def get_region(self):
        """ return the region """
        return self.store.get_region()

    def get_endpoint(self):
        """ return the end point fot the store """
        return self.store.get_endpoint()

    def get_name(self):
        """ return the name """
        return self.store.get_name()

    def get_type(self):
        """ return the type """
        return self.store.get_type()

    def default_bucket(self):
        """ the default bucket """
        return self.store.default_bucket()
    def change_value(self, key, value):
        """ change the internal config value """
        return self.store.change_value(key, value)

class EdgexConfig:
    """ Read the main config for the EdgexAccess """
    file_name = ""

    def __init__(self, cfg_filename):
        self.prog = "SP3"
        with open(cfg_filename, "r") as open_cfg:
            self.cfg_data = json.load(open_cfg)

        self.file_name = cfg_filename
        self.store_dict = {}
        stores = self.cfg_data['stores']
        for st_name in stores:
            self.store_dict[st_name['NAME']] = EdgexStore(st_name)

        if self.cfg_data['PRIMARY']:
            self.primary = self.cfg_data['PRIMARY']
        if self.cfg_data['DEBUG']:
            self.debug_level = self.cfg_data['DEBUG']
        if self.cfg_data['SYNCIO']:
            self.syncio = self.cfg_data['SYNCIO']
        if self.cfg_data['DATATEST']:
            self.datatest = self.cfg_data['DATATEST']
        if self.cfg_data['META']:
            self.meta = self.cfg_data['META']

        # setup the pwd store and the in-memory store
        store = self.create_store("pwd", "FS", os.getcwd(), tag="file")
        self.add_store("pwd", store)
        store = self.create_store("mem", "MEM", str(os.getpid()), tag="mem")
        self.add_store("MEM", store)

    def io_type(self):
        """ whether this is sync or async """
        return self.syncio

    def change_cfg_value(self, key, values):
        """ edit the key for this config """
        if len(values) > 0:
            self.cfg_data[key.upper()] = values[0]
        else:
            raise InvalidArgument(key)

    def change_store_value(self, st_name, var_name, var_value):
        """ Change one value in the sore """
        stores = self.cfg_data['stores']
        for sname in stores:
            if sname['NAME'] == st_name:
                stcfg = self.store_dict[sname['NAME']]
                stcfg.change_value(var_name, var_value)
                sname[var_name.upper()] = var_value
    def create_store(self, name, store_type, bucket, \
               access="", secret="", endpoint=None, \
               region="", token="", tag=""):
        """ create a store instance """

        if not name or not store_type or not bucket:
            raise InvalidArgument(name)

        scfg = {}
        scfg['NAME'] = name
        scfg['STORE_TYPE'] = store_type
        scfg['BUCKET'] = bucket

        # optional
        if store_type == 'S3':
            scfg['ACCESS'] = access
            scfg['SECRET'] = secret

        # optional
        scfg['ENDPOINT'] = endpoint
        scfg['REGION'] = region
        scfg['TOKEN'] = token
        scfg['TAG'] = tag

        # jcfg = json.dumps(scfg)
        if store_type == "FS":
            store = EdgexFSStore(scfg)
        elif store_type == "S3":
            store = EdgexS3Store(scfg)
        elif store_type == "MEM":
            store = EdgexMemStore(scfg)
        else:
            raise InvalidStore(store_type)

        return store

    def get_store(self, store_name):
        """ get me a store with this name from the dictionary """
        try:
            store = self.store_dict[store_name]
            return store
        except Exception as exp:
            logger.exception(exp)
            raise InvalidStore(store_name)

    def add_store(self, name, store):
        """ add this store object with a name as a key """
        self.store_dict[name] = store
        st_obj = {}
        st_obj['NAME'] = store.get_name()
        st_obj['STORE_TYPE'] = store.get_type()
        st_obj['BUCKET'] = store.default_bucket()
        st_obj["TOKEN"] = ""
        st_obj["TAG"] = ""
        if store.get_type() == "S3":
            st_obj["ACCESS"] = ""
            st_obj["SECRET"] = ""
            st_obj["REGION"] = ""
            st_obj["ENDPOINT"] = ""
        self.cfg_data['stores'].append(st_obj)

    def del_store(self, name):
        """ delete this store object with a name as a key """
        del self.store_dict[name]
        for k in self.cfg_data['stores']:
            if k['NAME'] == name:
                del k

    def get_pwd_store(self):
        """ return a store corresponding to the pwd in local store """
        return self.store_dict['pwd']

    def get_mem_store(self):
        """ return a store corresponding to the pwd in local store """
        return self.store_dict['mem']

    def get_primary_store(self):
        """ the name of the primary store """
        if self.cfg_data['PRIMARY'] is None:
            raise RuntimeError("No Primary Store defined")
        return self.store_dict[self.cfg_data['PRIMARY']]

    def get_meta_location(self):
        """ the location of metadata is chose to be stored """
        if self.cfg_data['META'] is None:
            raise RuntimeError("No Meta Store defined")
        return self.cfg_data['META']

    def get_datatest(self):
        """ this is the test/ directory """
        cwd = os.getcwd()
        dpath = cwd + "/" + self.datatest
        if not os.path.exists(dpath):
            os.makedirs(dpath)
        return dpath

    def show_store(self, store):
        """ show one store """
        logger.info(str("\t" + store.get_name() + "\t" + store.get_type() \
                            + "\t" + store.default_bucket()))

    def show_stores(self):
        """ show me all the stores """
        for k in self.store_dict:
            store = self.store_dict[k]
            self.show_store(store)

    def show_all(self):
        """ show all the stores """
        logger.info(str("primary:" + "\t" + self.primary))
        logger.info(str("debug_level: " + "\t" + str(self.debug_level)))
        logger.info(str("syncio :" + "\t" + self.syncio))
        logger.info("stores:")
        self.show_stores()

    def save(self):
        """ convert to a json format for saving """
        cfg_obj = {}
        cfg_obj["PROGRAM"] = self.prog
        for k in self.cfg_data:
            cfg_obj[k] = self.cfg_data[k]
            if k == 'stores':
                c = 0
                for st in cfg_obj[k]:
                    if st['NAME'] == "mem":
                        del cfg_obj[k][c]
                    if st['NAME'] == "pwd":
                        del cfg_obj[k][c]
                    c += 1
        with open(self.file_name, 'w') as outfile:
            json.dump(cfg_obj, outfile, indent=4, sort_keys=True)

class EdgexObjectName:
    """ Only define the name string of the obeject and
        parse out the store, bucket, objname, if it is a
        folder etc from it
        examples of names:

        aws3://xenocloud/foo/bar
            store is defined in the cfg as aws3 with all the credentials
            bucketname is xenocloud and the path tp the object bar is /foo/bar

        ix://mydir/foo/bar
            store is defined in the config as ix, as a Filesystem path
            bucket name ( folder name ) is mydir and the path to the file bar
            is /foo/bar

        The following two stes are automatically created and are not in the
        config

        mem://2324/stuff
            store is an im-memory store for pid 2324. Object is stuff.

        pwd://mydir/foo/bar
            store is the present working directory. Folder is mydir
            and the path to the object bar is /foo/bar

    """
    def __init__(self, name):
        if len(name) == 0:
            raise InvalidStore("Store not defined :" + name)
        self.oname = name
        self.objname = ""
        self.bucketname = ""
        self.storename = ""
        self.rpath = ""
        self.storename, self.rpath = self.parse_storename()
        self.bucketname, self.objname = self.parse_bucketobject()
        logger.debug(str("Store: " + self.storename + "\tBucket: " \
                         + self.bucketname + "\tObject: " \
                         + self.objname))

    def parse_storename(self):
        """ returns the store name and the remaining path
            the oname must be of the form
            store://bucket/obj/name/path
        """
        sname = self.oname.split(":")
        storename = ""
        rpath = ""
        if len(sname) == 2:
            storename = sname[0]
            rpath = sname[1]
        elif len(sname) == 1:
            # the format store://bucket/obj was not used
            rpath = sname[0]
        else:
            raise InvalidStore("Store not defined: " + sname[0])
        return storename, rpath

    def parse_bucketobject(self):
        """ returns the bucketname, objectname """
        bname = self.rpath.split("/")
        bucketname = ""
        objectname = ""
        if len(bname) > 1:
            bucketname = bname[2]
            objectname = "/".join(bname[3:])
            return bucketname, objectname
        raise InvalidBucketName(self.rpath)

    def isfolder(self):
        """ determine if this is a folder by the name only """
        return self.objname.endswith("/")

    def get_storename(self):
        """ return only the store name """
        return self.storename

    def get_objectname(self):
        """ return only the object name """
        return self.objname

    def get_bucketname(self):
        """ return only the bucket name """
        return self.bucketname


class EdgexObject:
    """ defines the main object as defined by the object name """

    def __init__(self, cfg, name, store=None):
        self.is_object = False
        self.cfg = cfg
        # contains the databuffer on one task only. .. not the entire content-length.
        self.databuf = None
        # used only to pass around in callbacks etc
        self.arg = None
        self.ctx = None

        # the entire thing as the name says
        self.pjname = EdgexObjectName(name)

        # the object name only
        self.obj_name = self.pjname.get_objectname()
        self.bucket_name = self.pjname.get_bucketname()

        if store is not None:
            self.store = store
        else:
            self.store = cfg.get_store(self.pjname.get_storename())
            if self.store is None:
                raise InvalidStore(store)

        if self.store is None:
            self.store = self.cfg.get_primary_store()
        if not self.bucket_name:
            logger.debug("No Bucket name")
            self.bucket_name = self.store.default_bucket()

        # time for the creation of this in-memory object
        tm_now = datetime.utcnow()
        self.amzdate = tm_now.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = tm_now.strftime('%Y%m%d') # Date w/o time, used in credential scope

        #logger.debug(str("OBJECT : " + self.pathname() + "\t" + str(self.datestamp)))
        logger.debug(str("OBJECT : " + self.pathname()))

    def treat_object(self):
        """ no recursion, just treat this as os an object plain as simple 
            even if it has the "/" suffix """
        self.is_object = True

    def isfolder(self):
        """ return of the entire object is a folder
            or if the bucket is only there
            or if only the store is listed
        """
        if self.is_object:
            return False

        if self.store.get_type() == "FS":
            return os.path.isdir(self.pathname())
        if self.obj_name:
            return self.pjname.isfolder()
        if self.bucket_name:
            return self.bucket_name.endswith("/")
        return False

    def islocal(self):
        """ return if this is a local object """
        if self.store == "FS":
            return os.path.isdir(self.pathname())
        return False

    def random_buffer(self):
        """ Initialize this with a random buffer from 1K - 8K """
        ksize = [1024, 2048, 4096, 8192]
        size_sz = random.choice(ksize)
        self.databuf = os.urandom(size_sz)

    def add_buffer(self, buffer):
        """ use this as a data buffer ... usually strings .."""
        self.databuf = buffer


    def get_store(self):
        """ return the store for this object """
        return self.store

    def store_type(self):
        """ return the type if available """
        return self.store.get_type()

    def bucketname(self):
        """ return the bucket name """
        return self.bucket_name

    def objname(self):
        """ return the object name """
        return self.obj_name

    def basename(self):
        """ return only the storename://bucketname of this object """
        if self.store.get_name() != "local":
            fpath = self.store.get_name() + "://" + self.bucket_name + "/"
        else:
            fpath = self.store.get_name() + ":/" + self.bucket_name + "/"
        return fpath

    def stat(self, create=False):
        """ For local cases see if it is there, else create a dir path """
        if self.store_type() == "FS":
            file_found = os.path.exists(self.pathname())
            if (file_found is False) and (create is True) and self.obj_name.endswith("/"):
                logger.info(str("mkdir " + self.pathname()))
                os.makedirs(self.pathname())
            else:
                return file_found
        else:
            logger.error(str("Error: No stat on store_type: " + self.store_type()))
            raise InvalidStore(str(self.store_type()))
        return ""

    def pathname(self):
        """ return the full path name of the object """
        if self.store_type() == "FS":
            fpath = self.store.get_endpoint() + "/" + self.bucket_name + "/" + self.obj_name
        elif self.store_type() == "S3":
            fpath = self.store.get_endpoint() + "/" + self.bucket_name + "/" + self.obj_name
        elif self.store_type() == "MEM":
            fpath = self.bucket_name + "/" + self.obj_name
        else:
            logger.error(str("Error: store_type: " + self.store_type()))
            raise InvalidStore(str(self.store_type()))
        return fpath

    # TODO: remove this later
    def auth(self):
        # auth = AWS4Auth(self.store.access, self.store.secret, self.store.region, 's3')
        auth = ""
        return auth

    # return only the name
    def addchild(self, child):
        """ create a child on this object """
        objname = self.store.get_name() + "://" + \
                    self.bucketname() + "/" + self.objname() + \
                    child
        childobj = EdgexObject(self.cfg, objname)
        return childobj


class EdgexAccess:
    """ the main edgex_access class with the main
        methods to list, get, put, delete etc
    """
    def __init__(self, obj):
        if obj is None:
            raise InvalidArgument(str(None))
        self.obj = obj

        store_t = obj.store_type()
        if store_t == "FS":
            self.obj_access = EdgexFSAccess(obj)
        elif store_t == "S3":
            self.obj_access = EdgexS3Access(obj)
        elif store_t == "MEM":
            self.obj_access = EdgexMemAccess(obj)
        else:
            raise InvalidStore(self.obj.store_type())

    async def list(self, session=None):
        """ List the elements in this folder """
        logger.info(str("list " + self.obj.pathname()))
        return await self.obj_access.list(session)
    async def put(self, session=None):
        """ put this object using the desired access """
        logger.info(str("put " + self.obj.pathname()))
        return await self.obj_access.put(session)
    async def get(self, session=None):
        """ get this object using the desired access """
        logger.info(str("get " + self.obj.pathname()))
        return await self.obj_access.get(session)
    async def delete(self, session=None):
        """ delete this object using the desired access """
        logger.info(str("delete " + self.obj.pathname()))
        return await self.obj_access.delete(session)
    async def exists(self, session=None):
        """ exists this object using the desired access """
        logger.info(str("exists " + self.obj.pathname()))
        return await self.obj_access.exists(session)
    async def info(self, session=None):
        """ info this object using the desired access """
        logger.info(str("info " + self.obj.pathname()))
        return await self.obj_access.info(session)

class EdgexMeta:
    """ This object is specific to meta data only """
    def __init__(self, cfg, vdb):
        """ Initialize """
        self.obj = EdgexMetaSQLite(cfg, vdb_file=vdb)
    def init(self):
        """ Initialize """
        self.obj.init()
    def put(self, key, value):
        """ put a key value to this meta store """
        self.obj.put(key, value)
    def get(self, key):
        """ retrieve the value for this key """
        return self.obj.get(key)
    def delete(self, key):
        """ delete the  element with this key """
        self.obj.delete(key)
    def show(self):
        """ display what we have """
        self.obj.show()
    def wipe(self):
        """ wipe out the entire store"""
        self.obj.deldb()


class EdgexDataAccess:
    """ main data access methods """
    cfg = None
    tasks = []

    def __init__(self, cfg, loop):
        self.cfg = cfg
        self.session = aiobotocore.get_session(loop=loop)
        self.loop = loop

    async def copy(self, source_obj, dest_obj, recursive=False):
        """ Copy one object from one store to another """
        if not source_obj or not dest_obj:
            raise InvalidArgument
        if recursive and source_obj.isfolder() and dest_obj.isfolder():
            contents = await self.ls(source_obj)
            logger.info(contents)
            for item in contents:
                child_source = source_obj.addchild(item)
                child_dest = dest_obj.addchild(item)
                self.tasks.append(await self.copy(child_source, child_dest, \
                                               child_source.isfolder()))
        else:
            try:
                source_obj.arg = dest_obj
                edgex_op = EdgexAccess(source_obj)
                databuf = await edgex_op.get(self.session)
                await self.gp_callback(self.session, 'get', source_obj, databuf)
                return True
            except Exception as exp:
                logger.exception(exp)
        return False

    async def wget(self, source_obj):
        """ Do the wget on a URL """
        if not source_obj:
            raise InvalidArgument
        try:
            edgex_op = EdgexAccess(source_obj)
            databuf = await edgex_op.get(self.session)
            await self.gp_callback(self.session, 'get', source_obj, databuf)
            return True
        except Exception as exp:
            logger.exception(exp)
        return False

    async def delete(self, source_obj, recursive=False, parent_obj=None):
        """ Delete the object from the store """
        if not source_obj:
            raise InvalidArgument
        if source_obj.isfolder():
            if recursive:
                contents = await self.ls(source_obj)
                if len(contents) == 0:
                    source_obj.treat_object()
                    self.tasks.append(await self.delete(source_obj, \
                    #asyncio.ensure_future(await self.delete(source_obj, \
                                                  recursive=False, \
                                                  parent_obj=source_obj))
                for item in contents:
                    child_source = source_obj.addchild(item)
                    #asyncio.create_task(self.delete(child_source, \
                    self.tasks.append(await self.delete(child_source, \
                    #asyncio.ensure_future(await self.delete(child_source, \
                                                      child_source.isfolder(), \
                                                      parent_obj=source_obj))
        else:
            try:
                edgex_op = EdgexAccess(source_obj)
                deleted = await edgex_op.delete(self.session)
                await self.cmd_callback('delete', source_obj, deleted)
            except Exception as exp:
                logger.exception(exp)
        if parent_obj:
            contents = await self.ls(parent_obj)
            if len(contents) == 0:
                parent_obj.treat_object()
                edgex_op = EdgexAccess(parent_obj)
                deleted = await edgex_op.delete(self.session)
                await self.cmd_callback('delete', parent_obj, deleted)

    async def ls(self, source_obj):
        """ List the object or a folder """
        try:
            edgex_op = EdgexAccess(source_obj)
            list_out = await edgex_op.list(self.session)
            contents = await self.cmd_callback('list', source_obj, list_out)
            return contents
        except Exception as exp:
            logger.exception(exp)
        return []

    async def get(self, source_obj, dest_obj):
        """ Get the object from the store """
        if not source_obj or not dest_obj:
            raise InvalidArgument
        try:
            source_obj.arg = dest_obj
            edgex_op = EdgexAccess(source_obj)
            databuf = await edgex_op.get(self.session)
            await self.gp_callback(self.session, 'get', source_obj, databuf)
            return True
        except Exception as exp:
            logger.exception(exp)
        return False
    async def put(self, source_obj, dest_obj):
        """ put the object into the store """
        if not source_obj or not dest_obj:
            raise InvalidArgument
        try:
            source_obj.arg = dest_obj
            edgex_op = EdgexAccess(source_obj)
            databuf = await edgex_op.put(self.session)
            await self.gp_callback(self.session, 'put', source_obj, databuf)

        except Exception as exp:
            logger.exception(exp)
        return False

    async def exists(self, source_obj):
        """ Check if this object exists in the store """
        if not source_obj:
            raise InvalidArgument
        try:
            edgex_op = EdgexAccess(source_obj)
            is_there = await edgex_op.exists(self.session)
            await self.cmd_callback('exists', source_obj, is_there)
            return is_there
        except Exception as exp:
            logger.exception(exp)
        return False

    async def info(self, source_obj):
        """ Get the metadata for the object as seen by the store """
        if not source_obj:
            raise InvalidArgument
        try:
            edgex_op = EdgexAccess(source_obj)
            obj_info = await edgex_op.info(self.session)
            await self.cmd_callback('info', source_obj, obj_info)
            return obj_info
        except Exception as exp:
            logger.exception(exp)
        return None

    async def gend(self, dest_obj):
        """ artificial random data generation """
        if not dest_obj:
            raise InvalidArgument
        try:
            # the genfile part of ofile should be the lastpart of the dest_obj name
            ofile = "MEM://" + str(os.getpid()) + "/genfile"
            mem_source_obj = EdgexObject(self.cfg, ofile)
            mem_source_obj.random_buffer()
            mem_source_obj.arg = dest_obj
            edgex_op = EdgexAccess(mem_source_obj)
            databuf = await edgex_op.get(self.session)
            await self.gp_callback(self.session, 'put', mem_source_obj, databuf)
            # now delete the in-memory object
            await edgex_op.delete(self.session)
        except Exception as exp:
            logger.exception(exp)
        return None

    async def cmd_callback(self, cmd, obj, result):
        """ single command callback """
        #logger.info(str(result))
        if cmd == 'list':
            return result
        if not obj:
            pass

    async def gp_callback(self, session, cmd, obj, result):
        """ get-put callback """
        try:
            if not cmd:
                pass
            dest_obj = obj.arg
            dest_obj.databuf = result
            edgex_op = EdgexAccess(dest_obj)
            put_obj = await edgex_op.put(session)
            await self.cmd_callback('put', dest_obj, put_obj)
        except Exception as exp:
            logger.exception(exp)

    def create_task(self, task_name, source_name, dest_name, recursive=False):
        """ Create a particular type of task or tasks if recursive """
        if task_name == 'gend':
            if recursive:
                gend_tcount = 60 # total
                gend_mcount = 10 # modcount
                mdpath = source_name + "/d0"
                for i in range(0, gend_tcount):
                    rfile = mdpath + "/dd" + str(i)
                    source_obj = EdgexObject(self.cfg, rfile)
                    self.tasks.append(self.gend(source_obj))
                    if (i % gend_mcount) == 0 and (i != 0):
                        mdpath = source_name + "/" + "d" + str(i)
            else:
                source_obj = EdgexObject(self.cfg, source_name)
                self.tasks.append(self.gend(source_obj))
        elif task_name == 'ls':
            source_obj = EdgexObject(self.cfg, source_name)
            self.tasks.append(self.ls(source_obj))
        elif task_name == 'wget':
            source_obj = EdgexObject(self.cfg, source_name)
            self.tasks.append(self.wget(source_obj))
        elif task_name == 'exists':
            source_obj = EdgexObject(self.cfg, source_name)
            self.tasks.append(self.exists(source_obj))
        elif task_name == 'info':
            source_obj = EdgexObject(self.cfg, source_name)
            self.tasks.append(self.info(source_obj))
        elif task_name == 'put':
            source_obj = EdgexObject(self.cfg, source_name)
            dest_obj = EdgexObject(self.cfg, dest_name)
            self.tasks.append(self.put(source_obj, dest_obj))
        elif task_name == 'get':
            source_obj = EdgexObject(self.cfg, source_name)
            dest_obj = EdgexObject(self.cfg, dest_name)
            self.tasks.append(self.get(source_obj, dest_obj))
        elif task_name == 'delete':
            source_obj = EdgexObject(self.cfg, source_name)
            self.tasks.append(self.delete(source_obj, recursive))
        elif task_name == 'copy':
            source_obj = EdgexObject(self.cfg, source_name)
            dest_obj = EdgexObject(self.cfg, dest_name)
            self.tasks.append(self.copy(source_obj, dest_obj, recursive))
        else:
            raise InvalidArgument(task_name)


    def execute(self):
        """ kick off the task list into the event q """
        self.loop.run_until_complete(asyncio.gather(*self.tasks))
