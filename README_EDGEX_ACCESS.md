
# edgex_access

## What is edgex_access

A Python3 connector library that uses the AWS S3 protocol to access data storage 
solutions like AWS S3, Minio and Azure BlobStore

- S3 configuration for more than one S3 store
- signature computation based on configuration
- S3 URI access for GET,PUT, DELETE
- Collective operations like copy, move

## edgex_access module

### Installing and Getting Started

Just to get you up and running on your local machine for development and testing. 

Install the edgex_access Python3 module

```bash
% pip3 install edgex_access
```

This package comes with a utility called "sp3" described below.
Other packages can depend on this and use the EdgexDataAccess API for object access into 
multiple store platforms.

## API for edgex_access


### EdgexConfig

Read in the configuration for accessing various S3 stores and 
other local data stores


```python

from os.path import expanduser
from edgex_access import EdgexConfig

cfg_file = expanduser("~") + /.mys3config
try:
	edgex_cfg = EdgexConfig(cfg_file)
except:
	print(" Error loading " + cfg_file  + " config file")

```

### EdgexStore

Each S3 store is represented as a EdgexStore, so once the confuration is read,
all the store instances are available

The configuration as a store marked as a primary S3 store. 

Example:
```python

primary_store = edgex_cfg.get_primary_store()
primary_store.show()
buckets = primary_store.list_buckets()

```

### EdgexObject

Each data object in any store is represented as an EdgexObject. At the time of 
the object creation , only the name is used. The EdgexObject uses the URI passed in 
and checks against the stores to determine which store this object is part of.

EdgexObject parses the URI to determine which store and bucket this is a part of


### edgex_access

edgex_access is a top level object which defines how each I/O operation
is executed. All main I/O Operations are available as different methods in 
this class.
e.g. list, delete, get, put

In addition to I/O operations, some execution can also be done using the 
threads in this pool 

Example:

Object Deletion 
---------------
```python

# define a callback when the operation is done
def my_cb(obj, result):
    print(obj.pathname() + " " + str(result))

# let's get a aio session 
session = aiobotocore.get_session(loop=loop)

# define the object
del_objname = "aws_s3://mybucket/file_foo.txt"
del_obj = EdgexObject(edgex_cfg, del_objname)

# access operation object
op = EdgexAccess(del_obj)

# make it happen 
deleted = await op.delete(session)

# let's wait on the callback 
await my_cb(edgex_obj, deleted)

```

Object Info
-----------

```python

# define a callback when the operation is done
def my_cb(obj, result):
    print(obj.pathname() + " " + str(result))

# let's get a aio session 
session = aiobotocore.get_session(loop=loop)

# define the object
del_objname = "aws_s3://mybucket/file_foo.txt"
del_obj = EdgexObject(edgex_cfg, del_objname)

# access operation object
op = EdgexAccess(del_obj)

# make it happen 
info = await op.info(session)

# let's wait on the callback 
await my_cb(edgex_obj, info)

```

As you can see the only difference between the above is 

```python
deleted = await op.delete(session)
```

```python
info = await op.info(session)
```

primarily the operation used in edgex_access


Now that we have done a single object operations like delete and info,
let's try to retrieve the object using get or place the object using put . 

Here is a "GET" example:

```python

# first we define the callback when 
# we place the data buffer we got

def put_callback(obj, result):
    print(obj.pathname() + " " + str(result))

# Now we define the callback to retrieve 
# the buffer of the object we are trying to 
# retrieve

def get_callback(session, obj, databuf):
    target_object = obj.arg
    target_object.databuf = databuf
    op = EdgexAccess(target_obj, logger)
    put_obj = await op.put(session)
    await put_callback(dest_obj, put_obj)

# start of the get operation 

get_objname = "aws_s3://mybucket/file_foo.txt"
get_obj = EdgexObject(edgex_cfg, del_objname)

op = EdgexAccess(source_obj)
databuf = await op.get(session)
await get_callback(session, source_obj, databuf)

```

As you can see from the example above, the object data buffer 
is retrieved and placed locally to the desired location using the 
"get" method in edgex_access. 

edgex_access is currently in development. Some of the features are missing and there are bugs 
Please refer to the 'Development Status" below.

### Development Status

- Most of the code for the API of edgex_access is defined and available. 
- A lot of tests will have to added in the fiture
- Most of the S3 I/O has been tested with Minio, AWS S3 and NexentaEdge
- If you see real issues while using edgex_access and sp3 , please do let us know


