#!/usr/bin/env python3
""" Unit tests for edgex_access """
#import unittest

import os
from os.path import expanduser
import sys
import getopt
import asyncio
import aiobotocore

import logzero
from logzero import logger
from logzero import logging

from edgex_access import EdgexHash
from edgex_access import EdgexConfig
from edgex_access import EdgexObject
from edgex_access import EdgexAccess
#from edgex_access import EdgexStore
#from edgex_access import EdgexMeta

DEFAULT_CONFIG = "/.sp3"

def init_config(cfg_file):
    """ Initialize the configuration """
    if not os.path.isfile(cfg_file) or not os.access(cfg_file, os.R_OK):
        logger.error(str("Unable to access: " + cfg_file))
        sys.exit(-2)
    if cfg_file is not None:
        with open(cfg_file, mode='r') as f_l:
            cfg_contents = f_l.read()
            cfg = EdgexConfig(cfg_contents)
            return cfg
    else:
        logger.error(str("Unable to access: " + cfg_file))
        sys.exit(-2)


#class TestEdgexAccess(unittest.TestCase):

async def cmd_callback(cmd, obj, result):
    """ generec callback for all commands """
    if cmd == list:
        logger.info(cmd + "\t" + obj.objname())
        logger.info(str("\t" + str(result)))


async def getput_callback(cmd, obj, databuf, session=None):
    """ get or put command callback ...once calls the other """
    try:
        logger.info(cmd + "\t" + obj.objname())
        logger.info(str("\t" + str(len(databuf))))
        dest_obj = obj.arg
        dest_obj.databuf = databuf
        edgex_op = EdgexAccess(dest_obj)
        put_obj = await edgex_op.put(session)
        await cmd_callback('put', dest_obj, put_obj)
    except Exception as exp:
        logger.exception(exp)


class TestEdgexAccess():
    """ Main Test class for the Unit test for EdgexAccess """
    gcfg = None
    maxcount = 0
    modcount = 0

    def __init__(self, cfg):
        """ set the config """
        self.gcfg = cfg
        self.maxcount = 50
        self.modcount = 10

    def bucketname(self, store_name):
        """ retrieve only the bucket name """
        store = self.gcfg.get_store(store_name)
        if store.get_type() == "FS":
            bname = ""
        else:
            bname = store.default_bucket()
        return bname

    async def genfile(self, store_name, session=None):
        """ generate a single file """
        ofile = "MEM://" + str(os.getpid()) + "/genfile"
        source_obj = EdgexObject(self.gcfg, ofile)
        source_obj.random_buffer()
        dfile = store_name + "://" + self.bucketname(store_name) + "/tdata" + "/" + "genfile"
        dest_obj = EdgexObject(self.gcfg, dfile)
        source_obj.arg = dest_obj
        logger.debug(source_obj.pathname())
        edgex_op = EdgexAccess(source_obj)
        databuf = await edgex_op.get(session)
        await getput_callback('put', source_obj, databuf, session)
    async def exists(self, store_name, session=None):
        """ check if the object exists """
        dfile = store_name + "://" + self.bucketname(store_name) + "/tdata" + "/" + "genfile"
        dest_obj = EdgexObject(self.gcfg, dfile)
        logger.debug(dest_obj.pathname())
        edgex_op = EdgexAccess(dest_obj)
        res = await edgex_op.exists(session)
        await cmd_callback('exists', dest_obj, res)
    async def info(self, store_name, session=None):
        """ retrieve the metadata infoon this object """
        dfile = store_name + "://" + self.bucketname(store_name) + "/tdata" + "/" + "genfile"
        dest_obj = EdgexObject(self.gcfg, dfile)
        logger.debug(dest_obj.pathname())
        edgex_op = EdgexAccess(dest_obj)
        res = await edgex_op.info(session)
        await cmd_callback('info', dest_obj, res)
    async def delete(self, store_name, session=None):
        """ delete this object """
        dfile = store_name + "://" + self.bucketname(store_name) + "/tdata" + "/" + "genfile"
        dest_obj = EdgexObject(self.gcfg, dfile)
        logger.debug(dest_obj.pathname())
        edgex_op = EdgexAccess(dest_obj)
        res = await edgex_op.delete(session)
        await cmd_callback('delete', dest_obj, res)
        res = await edgex_op.exists(session)
    async def putget(self, store_name, session=None):
        """ do a put get test """
        ofile = "MEM://" + str(os.getpid()) + "/buffer"
        source_obj = EdgexObject(self.gcfg, ofile)
        source_obj.random_buffer()
        dfile = store_name + "://" + self.bucketname(store_name) + "/tdata" + "/" + "buffer"
        dest_obj = EdgexObject(self.gcfg, dfile)
        source_obj.arg = dest_obj
        logger.debug(source_obj.pathname())
        edgex_op = EdgexAccess(source_obj)
        databuf = await edgex_op.get(session)
        await getput_callback('put', source_obj, databuf, session)
        h = EdgexHash()
        SIG1 = h.sha256(databuf)
        ofile = store_name + "://" + self.bucketname(store_name) + "/tdata" + "/" + "buffer"
        source_obj = EdgexObject(self.gcfg, ofile)
        logger.debug(source_obj.pathname())
        edgex_op = EdgexAccess(source_obj)
        databuf = await edgex_op.get(session)
        await cmd_callback('get', source_obj, databuf)
        h = EdgexHash()
        SIG2 = h.sha256(databuf)
        if SIG1 == SIG2:
            logger.debug(str("Match: " + SIG1))
        else:
            logger.error("Signature mismatch !!")
        # cleanup
        res = await edgex_op.delete(session)
        await cmd_callback('delete', dest_obj, res)
    async def rgenfile(self, store_name, session=None):
        """ recursive generation of a dir/file random data """
        dpath = store_name + "://" + self.bucketname(store_name) + "/tdata"
        mdpath = dpath + "/d0"
        for i in range(0, self.maxcount):
            ofile = "MEM://" + str(os.getpid()) + "/genfile"
            source_obj = EdgexObject(self.gcfg, ofile)
            source_obj.random_buffer()
            filename = mdpath +  "/" + "dd" + str(i)
            dest_obj = EdgexObject(self.gcfg, filename)
            source_obj.arg = dest_obj
            #logger.debug(dest_obj.pathname())
            edgex_op = EdgexAccess(source_obj)
            databuf = await edgex_op.get(session)
            await getput_callback('put', source_obj, databuf, session)
            if ((i % self.modcount) == 0) and (i != 0):
                mdpath = dpath + "/" + "d" + str(i)
    async def rinfo(self, store_name, session=None):
        """ recursive retrieval of metadata on the generated sample """
        dpath = store_name + "://" + self.bucketname(store_name) + "/tdata"
        mdpath = dpath + "/d0"
        for i in range(0, self.maxcount):
            filename = mdpath +  "/" + "dd" + str(i)
            d_obj = EdgexObject(self.gcfg, filename)
            logger.info(d_obj.pathname())
            edgex_op = EdgexAccess(d_obj)
            res = await edgex_op.info(session)
            await cmd_callback('info', d_obj, res)
    async def rexists(self, store_name, session=None):
        """ recursively check if the object exists """
        dpath = store_name + "://" + self.bucketname(store_name) + "/tdata"
        mdpath = dpath + "/d0"
        for i in range(0, self.maxcount):
            filename = mdpath +  "/" + "dd" + str(i)
            d_obj = EdgexObject(self.gcfg, filename)
            logger.info(d_obj.pathname())
            edgex_op = EdgexAccess(d_obj)
            res = await edgex_op.exists(session)
            await cmd_callback('exists', d_obj, res)
    async def rdelete(self, store_name, session=None):
        """ recursively delete the dir/file tree """
        dpath = store_name + "://" + self.bucketname(store_name) + "/tdata"
        mdpath = dpath + "/d0"
        for i in range(0, self.maxcount):
            filename = mdpath +  "/" + "dd" + str(i)
            d_obj = EdgexObject(self.gcfg, filename)
            logger.info(d_obj.pathname())
            edgex_op = EdgexAccess(d_obj)
            res = await edgex_op.delete(session)
            await cmd_callback('delete', d_obj, res)

    async def rputget(self, store_name, session=None):
        """ recursively run the put get with signature check """
        dpath = store_name + "://" + self.bucketname(store_name) + "/tdata"
        mdpath = dpath + "/d0"
        for i in range(0, self.maxcount):
            ofile = "MEM://" + str(os.getpid()) + "/buffer"
            source_obj = EdgexObject(self.gcfg, ofile)
            source_obj.random_buffer()
            dfile = mdpath +  "/" + "dd" + str(i)
            dest_obj = EdgexObject(self.gcfg, dfile)
            source_obj.arg = dest_obj
            logger.debug(source_obj.pathname())
            edgex_op = EdgexAccess(source_obj)
            databuf = await edgex_op.get(session)
            await getput_callback('put', source_obj, databuf, session)
            h = EdgexHash()
            SIG1 = h.sha256(databuf)
            ofile = dfile
            source_obj = EdgexObject(self.gcfg, ofile)
            logger.debug(source_obj.pathname())
            edgex_op = EdgexAccess(source_obj)
            databuf = await edgex_op.get(session)
            await cmd_callback('get', source_obj, databuf)
            h = EdgexHash()
            SIG2 = h.sha256(databuf)
            if SIG1 == SIG2:
                logger.debug(str("Match: " + SIG1))
            else:
                logger.error("Signature mismatch !!")
            # cleanup
            res = await edgex_op.delete(session)
            await cmd_callback('delete', dest_obj, res)


def usage():
    print(sys.argv[0] + "\t -d <level> -c ")
    print(sys.argv[0] + "\t -d <level> run <store_name>")

#TEST_CASES = ["genfile", "info", "exists", "delete", "putget"]

TEST_CASES = ["rgenfile", "rexists", "rinfo", "rdelete", "rputget"]

def show_cases():
    for i in TEST_CASES:
        print(i)

async def run_case(cfg, casename, store_name, session=None):
    taccess = TestEdgexAccess(cfg)
    fname = getattr(TestEdgexAccess, casename)
    await fname(taccess, store_name, session)

async def process_command(cfg, session, cmd, store_name):
    if cmd == "run":
        for tcase in TEST_CASES:
            await run_case(cfg, tcase, store_name, session)
    else:
        logger.error(str("Unknown command: " + cmd))

def main():
    assert sys.version_info >= (3, 5)
    debug_level = 5

    try:
        opts, remainder = getopt.getopt(sys.argv[1:], "hd:cr:", ["help", \
                                                               "debug", \
                                                               "cases"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        if o in ("-d", "--debug"):
            debug_level = int(a)
        if o in ("-c", "--cases"):
            show_cases()
            sys.exit(0)

    #if len(remainder) < 2:
    #    usage()
    #    sys.exit(2)

    if debug_level == 0:
        log_format = '%(color)s[%(levelname)1.1s %(asctime)s \
                %(module)s:%(lineno)d]%(end_color)s %(message)s'
        logfile = sys.argv[0] + ".log"
        logzero.logfile(logfile, maxBytes=1048576, backupCount=3, \
                        loglevel=logging.DEBUG, formatter=log_format)
        formatter = logzero.LogFormatter(fmt=log_format)
        logzero.setup_default_logger(level=logging.DEBUG, formatter=formatter)
    else:
        log_format = '%(message)s'
        formatter = logzero.LogFormatter(fmt=log_format)
        logzero.setup_default_logger(level=logging.INFO, formatter=formatter)

    logger.debug(str(sys.argv[0] + " started "))

    cmd = remainder[0]
    store_name = remainder[1]

    cfg_file = expanduser("~") + DEFAULT_CONFIG
    cfg = init_config(cfg_file)

    loop = asyncio.get_event_loop()
    # session = aiohttp.ClientSession(loop=loop)
    session = aiobotocore.get_session(loop=loop)
    tasks = [asyncio.ensure_future(process_command(cfg, session, cmd, store_name))]
    loop.run_until_complete(asyncio.gather(*tasks))
    #loop.run_forever()
    loop.close()

    logger.debug(str(sys.argv[0] + " done "))

if __name__ == '__main__':
    #unittest.main()
    main()
