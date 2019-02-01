# edgex_access

## What is edgex_access

A Python3 connector library that uses the AWS S3 protocol to access data storage 
solutions like AWS S3, NexentaEdge, Minio, Scality Zenko and Cloudian S3

- S3 configuration for more than one S3 store
- signature computation based on configuration
- S3 URI access for GET,PUT, DELETE
- Collective operations like copy, move

## edgex_access module

### Installing and Getting Started

Just to get you up and running on your local machine for development and testing. 

Install the edgex_access Python3 module

```bash
% pip install edgex_access
```

This package comes with a utility called "sp3" described below.
Other packages can depend on this and use the EdgexDataAccess API for object access into 
multiple store platforms.

link to the API

## s3p

A simple CLI that uses the edgex_access module for command line access to the S3 stores

- Command line access to s3 web services and POSIX API for file access
- edgex_access is the Python class used by s3p


```
usage: sp3 [-h] [-d DEBUG] [-r] [--version] [--ls ...] [--exists ...]
           [--info ...] [--put ...] [--get ...] [--delete ...] [--copy ...]
           [--move ...] [--wget ...] [--config ...] [--store ...] [--meta ...]
           [--gend ...] [--test ...]

S3/Posix data ls/put/get/delete/copy/move

optional arguments:
  -h, --help            show this help message and exit
  -d DEBUG, --debug DEBUG
                        debug value
  -r                    recursive run
  --version             show program's version number and exit
  --ls ...              Listing of this object or folder
  --exists ...          Listing of this object or folder
  --info ...            Listing of this object or folder
  --put ...             Put this object or the folder
  --get ...             Get this object or the folder
  --delete ...          Remove this object or the folder
  --copy ...            Copy one object or folder to another store
  --move ...            Move this object or folder to another store
  --wget ...            Get the URL object
  --config ...          Configure this utility
  --store ...           Create and Show existing stores
  --meta ...            MetaData store configuration
  --gend ...            Generate random data
  --test ...            General test

Manage data the same way on all data store platforms

```



## Getting Started

All the basic configuration for sp3 goes into the file ~/.sp3. All of the 
S3 ACCESS and SECRET resides in this file.

### Example use of s3p for configuration

Let's start with basic configuration 

```bash
% s3p --config ls
```

If a message like "Unable to access /Users/myuser/.sp3"  showed up, let's try to create a 
new configuration . 

```bash
% s3p --config create
```

Now look at the default config

```bash
% s3p --config ls
```

Let's create some stores we can use to place the data objects

First we will create a local S3 store using minio

```bash
% sp3 --store create minio S3 homes3
```

Now add the ACCESS and the SECRET

```bash
% sp3 --store edit minio access admin
% sp3 --store edit minio secret password
```

Now we will add the region and the endpoint we use 

```bash
% sp3 --store edit minio region us-east-1
% sp3 --store edit minio endpoint http://127.0.0.1:9000
% sp3 --store edit minio tag minio
```

Let's create a local POSIX access store

```bash
% sp3 --store create ixl FS /Users/myuser/ixb
% sp3 --store edit ixl tag ixl
````

### Example use of s3p for object data transfer

Let's upload a file to our primary S3 store

```bash
% s3p --put aws_s3://mybucket/file.txt file.txt
```

Now checkif it is there 

```bash
% s3p --exists aws_s3://mybucket/file.txt
```

Let's get the file back with a different name

```bash
% s3p --get aws_s3://mybucket/file.txt foo.txt
```

Now make sure the checksums match for both the files

```bash
% sum file.txt
% sum foo.txt
```

Cleanup the files now

```bash
% s3p --delete aws_s3://mybucket/file.txt
```

Now let's generate some random data. File sizes are randomly selected between
1K, 2K, 4K, 8K  and filled with randomm data. 

```bash
% sp3 -r --gend ixl://stuff/tdata
```

Now copy the entire directory tree into S3 

```bash
% sp3 -r --copy ixl://stuff/tdata/ minio://nabinix/tdata/
```

Now delete the entire local tree in the POSIX directory

```bash
% sp3 -r --delete ixl://stuff/tdata/
```


```bash
% sp3 -r --delete minio://nabinix/tdata/
```

Generate the random data directly on S3

```bash
% sp3 -r --gend minio://nabinix/tdata
```

Now delete this random data tree in S3 

```bash
% sp3 -r --delete minio://nabinix/tdata/
```

## Built With

* [requests](https://github.com/requests/requests) - Requests: HTTP for Humans
* [urllib3](https://github.com/shazow/urllib3) - HTTP client in Python


## API for edgex_access


### EdgexConfig

Read in the configuration for accessing various S3 stores and 
other local data stores


```python

from os.path import expanduser
from edgex_access import EdgexConfig

cfg_file = expanduser("~") + /.mys3config
edgex_cfg = EdgexConfig()
try:
	edgex_cfg.load_file(cfg_file)
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

### edgex_object

Each data object in any store is represented as an edgex_object. At the time of 
the object creation , only the name is used. The edgex_object uses the URI passed in 
and checks against the stores to determine which store this object is part of.

edgex_object parses the URI to determine which store and bucket this is a part of


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
del_obj = edgex_object(edgex_cfg, del_objname)

# access operation object
op = edgex_access(del_obj)

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
del_obj = edgex_object(edgex_cfg, del_objname)

# access operation object
op = edgex_access(del_obj)

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
    op = edgex_access(target_obj, logger)
    put_obj = await op.put(session)
    await put_callback(dest_obj, put_obj)

# start of the get operation 

get_objname = "aws_s3://mybucket/file_foo.txt"
get_obj = edgex_object(edgex_cfg, del_objname)

op = edgex_access(source_obj)
databuf = await op.get(session)
await get_callback(session, source_obj, databuf)

```

As you can see from the example above, the object data buffer 
is retrieved and placed locally to the desired location using the 
"get" method in edgex_access. 

edgex_access is currently in development. Some of the features are missing and there are bugs 
Please refer to the 'Development Status" below.

### Prerequisites & Requirements


You need Python 3.5 or later to use edgex_access.  You can have multiple Python
versions (2.x and 3.x) installed on the same system without problems.

In Ubuntu, you can install Python 3 like this:

    $ sudo apt-get install python3 python3-pip

Make sure you have Python3 installed. Please check the requirement.txt for a list of Python packages 
that should be pre-installed before edgex_access and s3p can be used. 

### Coding Style

The Hitchhiker's Guide to Python [ http://docs.python-guide.org/en/latest/writing/style/ ]

## Authors

* **nexenta** - *Initial work* - [edgex_pyconnector](https://github.com/Nexenta/edgex_pyconnector ) 


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Thanks to dyusupov

