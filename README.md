# sp3 & edgex_access

## sp3

- Access to AWS S3 using Python3 
- S3 configuration for multiple S3 stores like minio, zenko, cloudian and nexentaedge
- Very simple to use as a CLI 

```bash
% sp3 --copy -r myhome://photos/cabo/ aws3://photos/cabo
```

```bash
% sp3 --delete -r myhome://photos/cabo/
```

Please refer to [README_SP3.md](https://github.com/nacharya/edgex_access/blob/master/README.md) for details. 

## edgex_access

- A Python3 connector library that uses the AWS S3 protocol to access data storage 
- Provides a primary I/O library API that allows access to all platforms
- Access to different Stores, Config, DataAccess and basic elements for I/O access
  and object access
- Core API Objects like
  EdgexConfig, EdgexObject, EdgexDataAccess, EdgexAccess, EdgexHash
  that hides the underlying implemention of S3 and other proprietary access

Please refer to [README_SP3.md](https://github.com/nacharya/edgex_access/blob/master/README_EDGEX_ACCESS.md) for details. 

### Prerequisites & Requirements

You need Python 3.5 or later to use edgex_access.  You can have multiple Python
versions (2.x and 3.x) installed on the same system without problems.

In Ubuntu, you can install Python 3 like this:

    $ sudo apt-get install python3 python3-pip

Make sure you have Python3 installed. Please check the requirement.txt for a list of Python packages 
that should be pre-installed before edgex_access and s3p can be used. 

### Installation 

```bash
% pip install edgex_access
```

### Coding Style

The Hitchhiker's Guide to Python [ http://docs.python-guide.org/en/latest/writing/style/ ]

## Authors

* **nexenta** - *Initial work* - [edgex_pyconnector](https://github.com/Nexenta/edgex_pyconnector ) 


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Thanks to dyusupov

