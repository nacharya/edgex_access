s3p
========

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules

What is it ?
------------

It is a S3 command line utility written in Python 3 that will allow you to 
access data objects directly using the **edgex_access** API 

Configuration
-------------

They are kept in ~/.s3p and they look somewhat like the following

.. code-block:: json

        {
	        "stores" : [ 
	        {
		        "NAME" : "EDGEX-S3",
		        "STORE_TYPE" :"S3",
		        "ACCESS" : "CJSNOSIOJRQL2GXHFGZS",
		        "SECRET" : "waAMD0kGwbTAimeVcRNADORBhnVTMMMQQFCLZZwF",
		        "REGION" : "us-west-1",
		        "ENDPOINT" : "https://edge.nexenta.com",
		        "TOKEN" : "BCADDD34216",
		        "SSL" : "False",
		        "BUCKET" : "sample",
		        "TAG" : "edgex"
	        },
	        {
		        "NAME" : "HOME",
		        "STORE_TYPE" :"FS",
		        "TOKEN" : "ECBBDD3499",
		        "SSL" : "False",
		        "BUCKET" : "/Users/havanix",
		        "TAG" : "havanix"
	        }
	        ],
	        "PRIMARY" : "EDGEX-S3",
            "SYNCIO" : "SYNCIO",
	        "DEBUG" : 5
        }

Commands
--------
.. code-block:: sh

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



Command Options
---------------

-d <level>
        - Choose the debug level when the command is executed so the logs 
          available as s3p.log has the log entries based on this level 
        - if this option is not used no logs are generated as the default debug
          level is 5
        - maximum logging is available with level zero.

-r
        - the specified object is a directory or a folder and all remaining operations
          have to be done recursively on each object in the folder structure


.. code-block:: sh

        # get a remote file into a local store spefified as a store
        % s3p --get aws_s3://mybucket/file.txt HOME://somedir/file.txt

        # Let's get the same file in the present working directory 
        % s3p --get aws_s3://mybucket/file.txt file.txt


Command Usage Examples
----------------------

.. code-block:: sh

        # Create a bare bones setup template file ~/.s3p
        % s3p --config create 

        # See the setup 
        % s3p --config ls 

        # At this time please edit the configuration with the correct ACCESS, SECRET, URL etc 
        % vi ~/.s3p

        # Now look at the list of stores we have
        % s3p --store ls

        # Let see which store is primary 
        % s3p --store primary

        # Go through the list of buckets on this store
        % s3p --ls aws3://

        # Let's go through recursively a bucket and list it
        # Please note that if you want -r to go through the folder 
        # the folder must end with a "/" 
        % s3p --ls -r edgex://edge-FO-T/

        # Check and see if this object exists
        % s3p --exists edgex://edge-FO-T/signer.py

        # retrieve the metadata of the object
        % s3p --info edgex://edge-FO-T/signer.py

        # retrieve the object and write it locally to the current directory
        # this is where -l comes in 
        % s3p --get edgex://edge-FO-T/signer.py signer.py

        # delete the remote object
        % s3p --delete edgex://edge-FO-T/signer.py

        # take the local file and put it as an object to the remote location 
        % s3p --put edgex://edge-FO-T/signer.py signer.py

        # see if the file we placed to the remote exists 
        % s3p --exists edgex://edge-FO-T/signer.py

        # Retrieve the metadata for the remote object
        % s3p --info edgex://edge-FO-T/signer.py

        # let's see if this objects exists in another remote store
        % s3p --exists aws3://xenocloud/signer.py

        # Get the object from one remote store to another remote store
        % s3p --get edgex://edge-FO-T/signer.py aws3://xenocloud/signer.py

        # Let's see the meta info for this object in this different store
        % s3p --info aws3://xenocloud/signer.py

        # delete the object from this store
        % s3p --delete aws3://xenocloud/signer.py

        # Let's generate a directory of small files with random bits
        % s3p --gend aws3://mybucket/dirone/

        # Now put all the files in this directory to the remote store
        # let go down the directory recursively to find each file
        # and place it remotely.
        % s3p --copy -r edgex://edge-FO-T/dirone/ aws3://mybucket/dirone/

        # Delete the entire folder remotely
        % s3p --del -r edgex://edge-FO-T/dirone/

