"""
See:
    https://packaging.python.org/en/latest/distributing.html
    https://github.com/pypa/sampleproject
    https://hynek.me/articles/sharing-your-labor-of-love-pypi-quick-and-dirty/

"""

import sys
import os

import os.path as path

from setuptools import setup

if sys.version_info < (3, 0, 0):
    sys.stdout.write("Need Python3 or above. Detected: %s\n" \
                     % sys.version.split(None, 1)[0])
    raise RuntimeError("edgex_access is for Python 3")

HERE = path.abspath(path.dirname(__file__))
VPATH = os.path.join(HERE, 'edgex_access', 'version.py')
__version__ = eval(open(VPATH).read())


###################################################################
LONG_DESCRIPTION = "edgex_access: a Python library for accessing AWS using the S3 protocol"

# Get the long description from the README file
with open(path.join(HERE, 'README.md'), encoding='utf-8') as f:
    LONG_DESCRIPTION = f.read()

setup(
    name='edgex_access',
    version=__version__,
    description="S3 protocol Data access to AWS S3",
    long_description=LONG_DESCRIPTION,
    url="http://www.github.com/nacharya/edgex_access",
    author="Nabin Acharya",
    author_email="nabin.acharya@gmail.com",
    license="MIT",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
    ],
    scripts=['sp3/sp3'],
    keywords='requests edgex_access s3 scaleout store distributed',
    packages=['edgex_access'],
    python_requires='>=3',
    install_requires=['urllib3', 'requests_aws4auth', 'aiobotocore', \
                      'simplejson', 'lxml', 'asyncio'],
    include_package_data=True,
    project_urls={
        'Bug Reports': 'https://github.com/nacharya/edgex_access/issues',
        'Source': 'https://github.com/nacharya/edgex_access/',
    },
    zip_safe=False
)
