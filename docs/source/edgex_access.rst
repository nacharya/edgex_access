edgex_access
============

`edgex_access https://github.com/Nexenta/edgex_pyconnector` is S3 protocol client implementation in **Python 3** which uses
the latest available API of AWS S3 API

What is this ?
--------------

AWS S3 is a very popular protocol to read/write data objects on top of the 
HTTP protocol. `edgex_access https://github.com/Nexenta/edgex_pyconnector`  allows access to multiple S3 Services 
( not only Amazon ) to read/write data objects as efficiently as possible. 
It abstracts out the IO protocol so it is easier to access the data objects without 
attempting to understand the details of how to access the data objects

Installing
----------
.. code-block:: sh 

  pip3 install edgex_access


Loading a S3 configuration 
--------------------------

.. code-block:: python

   from edgex_access import edgex_config

   # This is how to load up the configuration 
   #
   cfg_file = expanduser("~") + "/.edgex_config"
   edgex_cfg = EdgexConfig(cfg_file)

   # look at the contents
   edgex_cfg.show_all() 


Doing stuff
-----------
.. code-block:: python

    # Let's define a callback when put is done
    async def put_callback(obj, result):
        print(obj.objname() + "\t" + str(result))

    # Let's a get a callback when we finish the reads first
    async def get_callback(session, obj, result):
        dest_obj = obj.arg
        dest_obj.databuf = result
        op = EdgexAccess(dest_obj)
        put_obj = await op.put(session)
        await put_callback(dest_obj, put_obj)

    # now do a PUT ising this
    remoteName="aws3://mybucket/foofile"
    localFile="foofile"
    source_obj = EdgexObject(remoteName)
    dest_obj = EdgexObject(localFile)

    op = EdgexAccess(source_obj)
    databuf = await op.get(session)
    await get_callback(session, source_obj, databuf)

    # Let's define a callback when exists is done
    async def exists_callback(obj, result):
        print(obj.objname() + "\t" + str(result))

    # let's see if the object made it to the remote
    dest_op = EdgexAccess(dest_obj)
    isthere = await dest_op.exists(session)
    await exists_callback(dest_obj, isthere)

API
====

Primary API in edgex_access module is in these objects:

EdgexAccess
EdgexDataAccess
EdgexConfig
EdgexStore
EdgexObject



EdgexAccess
        - Access S3 stores using the AWS S3 protocol using primary 
          API for list, exists, get, put, info, delete

EdgexConfig
        - Describe the confguration for all the S3 stores and Local Store load_file
        - Load a file configuration fromstreing
        - Load a JSON format string of configuration

EdgexStore
        - Describe one instance of store as describe in the configuration list_buckets
        - List a set of buckets for this store edgex_obj
        - Code edgex object for doing I/O exists
        - Check of the object exists in the store metainfo
        - Return the metadata for this object 

EdgexObject
        - Create an object instance based on the string representing the object. 
          Each string representation must have the store name or it is assumed to be
          picked up from the local present working directory if the flag is provided

Example
-------
.. code-block:: python

   objname = "aws_s3://mybucket"
   obj = EdgexObject(edgex_cfg, objname)
   print("URI : " + obj.pathname())
   print("Bucket : " + obj.bucketname())
   print("Object : " + obj.objname())


EdgexDataAccess
        - Do the I/O operations using these methods, and the object supplied
        - Does the I/O based on the store type to determine how to do the I/O

        Available methods:

        get
                - Retrieve the buffer for this object 
        read
                - Same as get
        put
                - Place a buffer into this object 
        write
                - Same as put
        remove
                - Delete this object from the store
        delete
                - Delete this object from the store
        exists
                - Check if the object actually exists or not
        info
                - Determine the meta only for this object
        copy
                - Copy data object from one store to another



