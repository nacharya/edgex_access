#!/usr/bin/env python3

import edgex_access
import unittest

class TestEdgexAccess(unittest.TestCase):
    def __init__(self):
        cfg_file = expanduser("~") + DEFAULT_CONFIG
        if not os.path.isfile(cfg_file) or not os.access(cfg_file, os.R_OK):
            logger.error("Unable to access " + cfg_file)
            sys.exit(2)
        if (cfg_file != None):
            with aiofiles.open(cfg_file, mode='r') as f:
                cfg_contents = f.read()
                cfg = edgex_config(cfg_contents)
        # generate the local setup
        pass
    def gen_file(self):
        # generate a local file and a signature
        pass
    def test_put(self):
        pass
    def test_exists(self):
        pass
    def test_info(self):
        pass
    def test_del_local(self):
        # file only not the signature
        pass
    def test_get(self):
        pass
    def test_verify(self):
        pass
    def test_del(self):
        pass


if __name__ == '__main__':
    unittest.main()
