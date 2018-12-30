""" The main edgex_access file that has all the classes used in this
    module.
"""
# Placed at the top as suggested by pylint
from xml.etree.ElementTree import fromstring as parse_xml, ParseError

import json
import os
import hashlib
from datetime import datetime
import async_timeout
import aiofiles
# import requests-aws4auth
from sqlitedict import SqliteDict
from logzero import logger


ACCESS_LOG_FILE = "edgex_access"
MAX_SINGLE_OBJ = 5* 1024 * 1024 * 1024 # 5Gb


#Error objects, Exceptions etc
#============================================================================

class EdgexException(Exception):
    """Base for exceptions returned by S3 servers"""

    @staticmethod
    def from_bytes(status, body):
        """
            extract the error from the xml response
        """
        if not body:
            raise RuntimeError("HTTP Error {}".format(status))
        try:
            xml = parse_xml(body)
        except ParseError:
            raise RuntimeError(body)
        code_el = xml.find("Code")
        if code_el is None or not code_el.text:
            raise RuntimeError(body)
        class_name = code_el.text
        try:
            cls = globals()[class_name]
        except KeyError:
            raise RuntimeError("Error {} is unknown".format(class_name))
        msg = xml.find("Message")
        return cls(class_name if msg is None else msg.text)


class AccessDenied(EdgexException):
    """Access is Denied"""
    pass
class AccountProblem(EdgexException):
    """Account has a problem"""
    pass
class AmbiguousGrantByEmailAddress(EdgexException):
    """ Grant looks Ambigious """
    pass
class BadDigest(EdgexException):
    """ Bad digest """
    pass
class BucketAlreadyExists(EdgexException):
    """ Bucket already exists  """
    pass
class BucketAlreadyOwnedByYou(EdgexException):
    """ Bucket is already owned by the same user """
    pass
class BucketNotEmpty(EdgexException):
    """ Bucket is not empty """
    pass
class CredentialsNotSupported(EdgexException):
    """ Credentials is not supported  """
    pass
class CrossLocationLoggingProhibited(EdgexException):
    """ Cross location logging is not allowed  """
    pass
class EntityTooSmall(EdgexException):
    """ Too small entity """
    pass
class EntityTooLarge(EdgexException):
    """ Too large entity  """
    pass
class ExpiredToken(EdgexException):
    """ Token has expired """
    pass
class IllegalVersioningConfigurationException(EdgexException):
    """ Version configuration is illegal """
    pass
class IncompleteBody(EdgexException):
    """ Incomplete body """
    pass
class IncorrectNumberOfFilesInPostRequest(EdgexException):
    """ Incorret number of files in the post request """
    pass
class InlineDataTooLarge(EdgexException):
    """ Inline data is too large """
    pass
class InternalError(EdgexException):
    """ Internal Error """
    pass
class InvalidAccessKeyId(EdgexException):
    """ Invalid Access  """
    pass
class InvalidAddressingHeader(EdgexException):
    """ Invalid Address header """
    pass
class InvalidArgument(EdgexException):
    """ Invalid Argument """
    pass
class InvalidBucketName(EdgexException):
    """ Invalid bucket name """
    pass
class InvalidBucketState(EdgexException):
    """ Invalid bucket state """
    pass
class InvalidDigest(EdgexException):
    """ Invalid digest """
    pass
class InvalidEncryptionAlgorithmError(EdgexException):
    """ Invalid encryption algorithm error """
    pass
class InvalidLocationConstraint(EdgexException):
    """ Invalid location constraint """
    pass
class InvalidObjectState(EdgexException):
    """ Invalid Object state """
    pass
class InvalidPart(EdgexException):
    """ Invalid part """
    pass
class InvalidPartOrder(EdgexException):
    """ Invalid part order """
    pass
class InvalidPayer(EdgexException):
    """ Invalid Player """
    pass
class InvalidPolicyDocument(EdgexException):
    """ Invalid policy """
    pass
class InvalidRange(EdgexException):
    """ Invalid range """
    pass
class InvalidRequest(EdgexException):
    """ Invalid request """
    pass
class InvalidSecurity(EdgexException):
    """ Invalid security """
    pass
class InvalidSOAPRequest(EdgexException):
    """ Invalid SOAP """
    pass
class InvalidStorageClass(EdgexException):
    """ Invalid Storage class """
    pass
class InvalidTargetBucketForLogging(EdgexException):
    """ Invalid target bucket """
    pass
class InvalidToken(EdgexException):
    """ Token is invalid """
    pass
class InvalidURI(EdgexException):
    """ URI is invalid """
    pass
class InvalidCommand(EdgexException):
    """ Command is invalid """
    pass
class InvalidStore(EdgexException):
    """ Store is invalid """
    pass
class KeyTooLong(EdgexException):
    """ Key is too long """
    pass
class MalformedACLError(EdgexException):
    """ACL is malformed  """
    pass
class MalformedPOSTRequest(EdgexException):
    """ POST request is malformed """
    pass
class MalformedXML(EdgexException):
    """ XML is malformed """
    pass
class MaxMessageLengthExceeded(EdgexException):
    """ Message length has exceeded the max """
    pass
class MaxPostPreDataLengthExceededError(EdgexException):
    """ POST predata length exceeded the error """
    pass
class MetadataTooLarge(EdgexException):
    """ Too large metadata """
    pass
class MethodNotAllowed(EdgexException):
    """ Method is not allowed """
    pass
class MissingAttachment(EdgexException):
    """ Attachment is missing  """
    pass
class MissingContentLength(EdgexException):
    """ COntent length is missing """
    pass
class MissingRequestBodyError(EdgexException):
    """ Request body is missing  """
    pass
class MissingSecurityElement(EdgexException):
    """ Security element is missing """
    pass
class MissingSecurityHeader(EdgexException):
    """ Secirity header is missing """
    pass
class NoLoggingStatusForKey(EdgexException):
    """ No logging status for this key """
    pass
class NoSuchBucket(EdgexException):
    """ No such bucket """
    pass
class NoSuchKey(EdgexException):
    """ No such key """
    pass
class NoSuchLifecycleConfiguration(EdgexException):
    """ No such life cycle configuration  """
    pass
class NoSuchUpload(EdgexException):
    """ No suck upload """
    pass
class NoSuchVersion(EdgexException):
    """ No such version  """
    pass
class NotSignedUp(EdgexException):
    """ Not signed up """
    pass
class NotSuchBucketPolicy(EdgexException):
    """ No such bucket """
    pass
class OperationAborted(EdgexException):
    """ Operation aborted """
    pass
class PermanentRedirect(EdgexException):
    """ Permanent redirect """
    pass
class PreconditionFailed(EdgexException):
    """ Precondition failed """
    pass
class Redirect(EdgexException):
    """ Redirect """
    pass
class RestoreAlreadyInProgress(EdgexException):
    """ Restore is already in progress """
    pass
class RequestIsNotMultiPartContent(EdgexException):
    """ Request is not multi-part content """
    pass
class RequestTimeout(EdgexException):
    """ Request timeout """
    pass
class RequestTimeTooSkewed(EdgexException):
    """ Request time is skewed """
    pass
class RequestTorrentOfBucketError(EdgexException):
    """ Request torrent bucket error """
    pass
class SignatureDoesNotMatch(EdgexException):
    """ Signature mis-match  """
    pass
class ServiceUnavailable(EdgexException):
    """ Service is unavailable """
    pass
class SlowDown(EdgexException):
    """ Slow down """
    pass
class TemporaryRedirect(EdgexException):
    """ Temporary redirect """
    pass
class TokenRefreshRequired(EdgexException):
    """ Token needs to be refreshed """
    pass
class TooManyBuckets(EdgexException):
    """ Too many buckets """
    pass
class UnexpectedContent(EdgexException):
    """ Unexpected content """
    pass
class UnresolvableGrantByEmailAddress(EdgexException):
    """ Unresolved Grant by email  """
    pass
class UserKeyMustBeSpecified(EdgexException):
    """ User key must be specified """
    pass
class EmptyTag(EdgexException):
    """ Tag is empty """
    pass

# ============================================================================
# Error End

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

class EdgexStoreBase:
    """ Base class for Store definition """
    def __init__(self, cfg):
        self.name = cfg['NAME']
        self.type = cfg['STORE_TYPE']
        #if (self.type != "FS") or (self.type != "S3"):
        #    raise InvalidStore(self.type)
        self.bucket = cfg['BUCKET']
        self.token = cfg['TOKEN']
        self.tag = cfg['TAG']
        if not self.tag:
            raise EmptyTag(self.tag)

    def islocal(self):
        """ is this a local filesystem """
        return self.type == "FS"

    def get_tag(self):
        """ tag is the short name we use """
        return self.tag
    def get_name(self):
        """ Get the name """
        return self.name
    def get_type(self):
        """ Get the type """
        return self.type
    def default_bucket(self):
        """ Get the named default bucket """
        return self.bucket

class EdgexFSAccess(EdgexStoreBase):
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

class EdgexS3Access(EdgexStoreBase):
    """ Security credentials to access the
        store
    """
    def __init__(self, cfg):
        super().__init__(cfg)
        self.access = cfg['ACCESS']
        self.secret = cfg['SECRET']
        self.region = cfg['REGION']
        self.endpoint = cfg['ENDPOINT']
    def get_endpoint(self):
        return self.endpoint
    def get_region(self):
        return self.region
    def get_access(self):
        return self.access
    def get_secret(self):
        return self.secret

class EdgexStore:
    """ Specific description of each store """

    def __init__(self, cfg):
        if cfg['STORE_TYPE'] == "S3":
            self.store = EdgexS3Access(cfg)
        elif cfg['STORE_TYPE'] == "FS":
            self.store = EdgexFSAccess(cfg)
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


class EdgexConfig:
    """ Read the main config for the EdgexAccess """

    def __init__(self, cfg_filedata):
        self.cfg_data = json.loads(cfg_filedata)
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
            self.datatest = self.cfg_data['META']

    def create(self, name, store_type, bucket, access="", secret="",\
            endpoint=None, region="", token="", tag=""):
        """ create a store instance """
        scfg = {}
        scfg['STORE_TYPE'] = store_type
        scfg['ACCESS'] = access
        scfg['SECRET'] = secret
        scfg['REGION'] = region
        scfg['ENDPOINT'] = endpoint
        scfg['USE_SSL'] = ""
        scfg['TOKEN'] = token
        scfg['TAG'] = tag
        scfg['NAME'] = name
        scfg['BUCKET'] = bucket

        # jcfg = json.dumps(scfg)
        if store_type == "FS":
            store = EdgexFSAccess(scfg)
        elif store_type == "S3":
            store = EdgexFSAccess(scfg)
        else:
            raise InvalidStore(store_type)

        return store


    def get_primary_store(self):
        """ the name of the primary store """
        if self.cfg_data['PRIMARY'] is None:
            raise RuntimeError("No Primary Store defined")
        return self.store_dict[ self.cfg_data['PRIMARY']]

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

    def show_stores(self):
        """ show me all the stores """
        for k in self.store_dict:
            store = self.store_dict[k]
            logger.info("\t" + store.get_name() + "\t" + store.get_type() + "\t" + store.default_bucket())

    def get_stores(self):
        """ get the stores as a list """
        ret = []
        for k in self.store_dict:
            store = self.store_dict[k]
            ret.append(store.name)
        return ret

    def get_store(self, store_name):
        """ get me a store with this name from the dictionary """
        try:
            store = self.store_dict[store_name]
            return store
        except Exception as exp:
            logger.exception(exp)
            return None

    # TODO: revise
    def get_local_pwd(self):
        """ return a store corresponding to the pwd in local store """
        store = self.create("file", "FS", os.getcwd(), tag="file")
        self.store_dict["file"] = store
        return store

    def show_all(self):
        """ show all the stores """
        logger.info(str("primary:" + "\t" + self.primary))
        logger.info(str("debug_level: " + "\t" + str(self.debug_level)))
        logger.info(str("syncio :" + "\t" + self.syncio))
        logger.info("stores:")
        self.show_stores()

class EdgexObjectName:
    """ Only define the name string of the obeject and
        parse out the store, bucket, objname, if it is a
        folder etc from it
    """
    def __init__(self, name):
        self.oname = name
        self.objname = ""
        self.bucketname = ""
        self.storename = ""
        rpath = ""
        self.storename, rpath = self.parse_storename()
        self.bucketname, self.objname = self.parse_bucketobject(rpath)

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

    def parse_bucketobject(self, bpath):
        """ returns the bucketname, objectname """
        bname = bpath.split("/")
        bucketname = ""
        objectname = ""
        if len(bname) > 1:
            bucketname = bname[1]
            objectname = "/".join(bname[2:])
        else:
            raise InvalidBucketName(bpath)
        return bucketname, objectname

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

    def __init__(self, cfg, name, store=None, as_is=False):
        self.oname = name
        self.as_is = as_is
        self.cfg = cfg
        # contains the databuffer on one task only. .. not the entire content-length.
        self.databuf = None
        # used only to pass around in callbacks etc
        self.arg = None
        self.ctx = None

        if self.localpath() is True:
            return

        # the entire thing
        self.pjname = EdgexObjectName(name)

        # the object name only
        self.obj_name = self.pjname.get_objectname()
        self.bucket_name = self.pjname.get_bucketname()

        if store is not None:
            self.store = store
        else:
            self.store = cfg.get_store(self.pjname.get_storename())

        if not self.bucket_name:
            if self.store.get_type() != "FS":
                logger.debug("No Bucket name")
            elif self.store.get_type() == "FS":
                self.bucket_name = self.store.default_bucket()

        # time for the creation of this in-memory object
        tm_now = datetime.utcnow()
        self.amzdate = tm_now.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = tm_now.strftime('%Y%m%d') # Date w/o time, used in credential scope

        logger.debug(str("OBJECT : " + self.pathname()))

        if self.store is None and self.as_is is False:
            self.store = self.cfg.get_primary_store()
            self.bucket_name = self.store.default_bucket()

    def isfolder(self):
        """ return of the entire object is a folder
            or if the bucket is only there
            or if only the store is listed
        """
        if self.store.get_type() == "FS":
            return os.path.isdir(self.pathname())
        if self.obj_name:
            return self.pjname.isfolder()
        if self.bucket_name:
            return self.bucket_name.endswith("/")

        return False

    def localpath(self):
        """ if this name is an entirely local pathname """
        if self.as_is is True:
            self.obj_name = self.oname
            self.bucket_name = os.getcwd()
            self.store = self.cfg.get_local_pwd()
            return True
        else:
            return False

    def get_store(self):
        """ return the store for this object """
        return self.store

    def store_type(self):
        """ return the type if available """
        return self.store.get_type()

    def bucketname(self):
        """ return the bucket name """
        if self.bucket_name:
            return self.bucket_name
        else:
            return self.store.default_bucket()

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
            fpath = self.bucket_name + "/" + self.obj_name
        elif self.store_type() == "S3":
            fpath = self.store.get_endpoint() + "/" + self.bucket_name + "/" + self.obj_name
        else:
            logger.error(str("Error: store_type: " + self.store_type()))
            raise InvalidStore(str(self.store_type()))
        return fpath

    def isobjlocal(self):
        """ return if this is a local object """
        if self.store == "FS":
            return os.path.isdir(self.objname)
        else: # could be local but has a store name
            return self.islocal

    def auth(self):
        # auth = AWS4Auth(self.store.access, self.store.secret, self.store.region, 's3')
        auth = ""
        return auth

    # return only the name
    def addchild(self, child):
        """ create a child on this object """
        if self.store_type() == "FS":
            objname = "//" + str(self.pathname()) + child
        elif self.store_type() == "S3":
            objname = self.basename() + self.objname() + child
        else:
            raise InvalidStore(str(self.store_type()))
        childobj = EdgexObject(self.cfg, objname, store=self.store)
        return childobj

    # Huh!?! Revise this
    def makefolder(self):
        """ make it look like a folder if it is not """
        if not self.isfolder and self.oname.endswith("/"):
            self.oname += "/"
            #self.isfolder = True


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

class EdgexAccess:
    """ the main edgex_access class with the main
        methods to list, get, put, delete etc
    """
    def __init__(self, obj):
        if obj is None:
            raise InvalidArgument(str(None))
        self.obj = obj

    async def list(self, session):
        """ List the elements in this folder """
        if session is None:
            raise InvalidArgument(str(session))
        logger.info(str("list " + self.obj.pathname()))
        final_list = []
        if self.obj.store_type() == "FS":
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

        elif self.obj.store_type() == "S3":

            async with session.create_client('s3', region_name=self.obj.store.get_region(), \
                                aws_secret_access_key=self.obj.store.get_secret(), \
                                aws_access_key_id=self.obj.store.get_access(), \
                                endpoint_url=self.obj.store.get_endpoint()) as client:

                prefix = self.obj.objname()
                resp = await client.list_objects(Bucket=self.obj.bucketname(), \
                                                 Prefix=prefix, Delimiter='/')
                retcode = resp['ResponseMetadata']['HTTPStatusCode']
                if retcode != 200:
                    raise RuntimeError("HTTP Error {}".format(retcode))

                if 'CommonPrefixes' in resp:
                    for r_x in resp['CommonPrefixes']:
                        if prefix.endswith('/') and prefix and (prefix != r_x['Prefix']):
                            final_list.append(r_x['Prefix'].replace(prefix, ''))
                        elif not prefix:
                            final_list.append(r_x['Prefix'])
                        else:
                            dlist = r_x['Prefix'].split('/')
                            if dlist:
                                if len(dlist[-1]) > 0:
                                    final_list.append(dlist[-1])
                                elif len(dlist[-2]) > 0:
                                    final_list.append(dlist[-2])
                            else:
                                final_list.append(r_x['Prefix'])
                elif 'Contents' in resp:
                    for r_x in resp['Contents']:
                        if prefix.endswith('/') and prefix:
                            final_list.append(r_x['Key'].replace(prefix, ''))
                        else:
                            dlist = r_x['Key'].split('/')
                            if dlist:
                                final_list.append(dlist[-1])
                            else:
                                final_list.append(r_x['Prefix'])
                return final_list

        else:
            raise InvalidStore(self.obj.store_type())

    async def exists(self, session):
        """ if the object exists """
        if session is None:
            raise InvalidArgument(str(session))
        logger.info(str("exists " + self.obj.pathname()))
        if self.obj.store_type() == "FS":
            return self.obj.stat()
        elif self.obj.store_type() == "S3":
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                        aws_secret_access_key=self.obj.store.secret, \
                                        aws_access_key_id=self.obj.store.access, \
                                        endpoint_url=self.obj.store.endpoint) as client:
                try:
                    hd = await client.head_object(Bucket=self.obj.bucketname(),\
                                                  Key=self.obj.objname())
                    retcode = hd['ResponseMetadata']['HTTPStatusCode']
                    return retcode == 200
                except:
                    return False
        else:
            raise InvalidArgument(self.obj.store_type())

    async def delete(self, session):
        """ delete this object """
        if session is None:
            raise InvalidArgument(str(session))

        logger.info(str("delete " + self.obj.pathname()))
        if self.obj.store_type() == "FS":
            if os.path.isfile(self.obj.pathname()):
                os.remove(self.obj.pathname())
                return True
            if os.path.isdir(self.obj.pathname()):
                dentries = os.listdir(self.obj.pathname())
                if not dentries:
                    os.rmdir(self.obj.pathname())

        elif self.obj.store_type() == "S3":

            async with session.create_client('s3', region_name=self.obj.store.region, \
                                            aws_secret_access_key=self.obj.store.secret, \
                                            aws_access_key_id=self.obj.store.access, \
                                            endpoint_url=self.obj.store.endpoint) as client:
                try:
                    del_obj = await client.delete_object(Bucket=self.obj.bucketname(), \
                                                         Key=self.obj.objname())
                    retcode = del_obj['ResponseMetadata']['HTTPStatusCode']
                    return retcode in (200, 204)
                except Exception as exp:
                    return False
        else:
            raise InvalidArgument(self.obj.store_type())

    async def info(self, session):
        """ get the underlying meta info on the object """
        if session is None:
            raise InvalidArgument(str(session))
        logger.info(str("info " + self.obj.pathname()))
        if self.obj.store_type() == "FS":
            if self.obj.stat() is True:
                metadata = {self.obj.pathname():os.stat(self.obj.pathname())}
                return metadata
            else:
                return None
        elif self.obj.store_type() == "S3":
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                        aws_secret_access_key=self.obj.store.secret, \
                                        aws_access_key_id=self.obj.store.access, \
                                        endpoint_url=self.obj.store.endpoint) as client:
                try:
                    hd = await client.head_object(Bucket=self.obj.bucketname(),\
                                                  Key=self.obj.objname())
                    retcode = hd['ResponseMetadata']['HTTPStatusCode']
                    if retcode == 200:
                        return hd['ResponseMetadata']['HTTPHeaders']
                    else:
                        return None
                except Exception as exp:
                    return None
        else:
            raise InvalidArgument(self.obj.store_type())

    async def get(self, session):
        """ get the object """
        if session is None:
            raise InvalidArgument(str(session))
        logger.info(str("get " + self.obj.pathname()))

        if self.obj.store_type() == "FS":
            file_size = os.stat(self.obj.pathname()).st_size
            if file_size > MAX_SINGLE_OBJ:
                raise EntityTooLarge(str(file_size))
            async with aiofiles.open(self.obj.pathname(), mode='r', encoding="latin-1") as f_l:
                file_data = await f_l.read()
            f_l.close()
            return file_data

        elif self.obj.store_type() == "S3":
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                                aws_secret_access_key=self.obj.store.secret, \
                                                aws_access_key_id=self.obj.store.access, \
                                                endpoint_url=self.obj.store.endpoint) as client:
                try:
                    with async_timeout.timeout(10):
                        gobj = await client.get_object(Bucket=self.obj.bucketname(),\
                                                       Key=self.obj.objname())
                        body = await gobj['Body'].read()
                        gobj['Body'].close()
                        return body
                except Exception as exp:
                    logger.exception(exp)
                    raise exp
        else:
            raise InvalidArgument(self.obj.store_type())

    async def put(self, session):
        """ put the object """
        if session is None:
            raise InvalidArgument(str(session))

        logger.info(str("put " + self.obj.pathname()))
        isdbuf = (self.obj.databuf is not None)
        isarg = (self.obj.arg is not None)

        logger.info(str("put " + self.obj.pathname() + \
                        " databuf " + str(isdbuf)))
        logger.info(str("put " + self.obj.pathname() + \
                        " arg " + str(isarg)))

        if not isdbuf:
            if self.obj.store_type() == "FS":
                try:
                    os.makedirs(os.path.dirname(self.obj.pathname()))
                except Exception as exp:
                    logger.exception(exp)
                    raise exp
                return self.obj.pathname()
            else:
                logger.error(str("No databuf : " + self.obj.pathname()))
                raise InvalidArgument(str(self.obj.pathname()))

        if (self.obj.store_type() == "FS"):
            if not os.path.exists(os.path.dirname(self.obj.pathname())):
                try:
                    os.makedirs(os.path.dirname(self.obj.pathname()))
                except Exception as exp:
                    logger.exception(exp)
                    raise exp
                open(self.obj.pathname(), 'wb').write(self.obj.databuf)

            return self.obj.pathname()

        elif self.obj.store_type() == "S3":

            async with session.create_client('s3', region_name=self.obj.store.region, \
                                                aws_secret_access_key=self.obj.store.secret, \
                                                aws_access_key_id=self.obj.store.access, \
                                                endpoint_url=self.obj.store.endpoint) as client:
                try:
                    with async_timeout.timeout(10):
                        await client.put_object(Bucket=self.obj.bucketname(), \
                                                        Key=self.obj.objname(), \
                                                        Body=self.obj.databuf)
                    return self.obj.pathname()

                except Exception as exp:
                    logger.exception(exp)
                    raise exp
        else:
            raise InvalidArgument(self.obj.store_type())
