
''' S3 specific functions '''

import os
import aiobotocore
import async_timeout

from logzero import logger
from .edgex_exceptions import *
from .edgex_base import EdgexStoreBase, EdgexAccessBase

class EdgexS3Store(EdgexStoreBase):
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

class EdgexS3Access(EdgexAccessBase):
    """ S3 protocol access """
    def __init__(self, obj):
        super().__init__(obj, "S3")
    async def list(self, session=None):
        """ List the elements """
        final_list = []
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
    async def put(self, session=None):
        isdbuf = (self.obj.databuf is not None)
        
        logger.info(str("put " + self.obj.pathname() + \
                        " databuf " + str(isdbuf)))
        if not isdbuf:
            try:
                os.makedirs(os.path.dirname(self.obj.pathname()))
            except Exception as exp:
                logger.exception(exp)
                raise exp
            logger.error(str("No data buffer for " + self.obj.pathname()))
            return self.obj.pathname()
        async with session.create_client('s3', region_name=self.obj.store.get_region(), \
                                            aws_secret_access_key=self.obj.store.get_secret(), \
                                            aws_access_key_id=self.obj.store.get_access(), \
                                            endpoint_url=self.obj.store.get_endpoint()) as client:
            try:
                with async_timeout.timeout(10):
                    await client.put_object(Bucket=self.obj.bucketname(), \
                                                    Key=self.obj.objname(), \
                                                    Body=self.obj.databuf)
                return self.obj.pathname()
            except Exception as exp:
                logger.exception(exp)
                raise exp

    async def get(self, session=None):
        async with session.create_client('s3', region_name=self.obj.store.get_region(), \
                                            aws_secret_access_key=self.obj.store.get_secret(), \
                                            aws_access_key_id=self.obj.store.get_access(), \
                                            endpoint_url=self.obj.store.get_endpoint()) as client:
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

    async def delete(self, session=None):
        """ delete this object """
        async with session.create_client('s3', region_name=self.obj.store.get_region(), \
                                        aws_secret_access_key=self.obj.store.get_secret(), \
                                        aws_access_key_id=self.obj.store.get_access(), \
                                        endpoint_url=self.obj.store.get_endpoint()) as client:
            try:
                del_obj = await client.delete_object(Bucket=self.obj.bucketname(), \
                                                     Key=self.obj.objname())
                retcode = del_obj['ResponseMetadata']['HTTPStatusCode']
                return retcode in (200, 204)
            except Exception as exp:
                return False

    async def exists(self, session):
        async with session.create_client('s3', region_name=self.obj.store.get_region(), \
                                    aws_secret_access_key=self.obj.store.get_secret(), \
                                    aws_access_key_id=self.obj.store.get_access(), \
                                    endpoint_url=self.obj.store.get_endpoint()) as client:
            try:
                hd = await client.head_object(Bucket=self.obj.bucketname(),\
                                              Key=self.obj.objname())
                retcode = hd['ResponseMetadata']['HTTPStatusCode']
                return retcode == 200
            except:
                return False

    async def info(self, session=None):
        async with session.create_client('s3', region_name=self.obj.store.get_region(), \
                                    aws_secret_access_key=self.obj.store.get_secret(), \
                                    aws_access_key_id=self.obj.store.get_access(), \
                                    endpoint_url=self.obj.store.get_endpoint()) as client:
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
