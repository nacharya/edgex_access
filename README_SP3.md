## sp3

A simple CLI that uses the edgex_access module for command line access to the S3 stores

- Command line access to s3 web services and POSIX API for file access
- edgex_access is the Python class used by sp3


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

### Example use of sp3 for configuration

Let's start with basic configuration 

```bash
% sp3 --config ls
```

If a message like "Unable to access /Users/myuser/.sp3"  showed up, let's try to create a 
new configuration . 

```bash
% sp3 --config create
```

Now look at the default config

```bash
% sp3 --config ls
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

### Example use of sp3 for object data transfer

Let's upload a file to our primary S3 store

```bash
% sp3 --put aws_s3://mybucket/file.txt file.txt
```

Now checkif it is there 

```bash
% sp3 --exists aws_s3://mybucket/file.txt
```

Let's get the file back with a different name

```bash
% sp3 --get aws_s3://mybucket/file.txt foo.txt
```

Now make sure the checksums match for both the files

```bash
% sum file.txt
% sum foo.txt
```

Cleanup the files now

```bash
% sp3 --delete aws_s3://mybucket/file.txt
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

