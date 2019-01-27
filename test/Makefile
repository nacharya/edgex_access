# Makefile for running unit tests
#

BASH=bash
PYTHON=python
SP3=sp3

all: unit_scripts

unit_scripts:
	$(BASH) sp3_test_config
	$(BASH) sp3_test_basic_1
	#$(BASH) sp3_test_basic_2

utests:
	$(PYTHON) test_access.py run pwd
	$(PYTHON) test_access.py run ix
	$(PYTHON) test_access.py run minio
	#$(PYTHON) test_access.py run aws3
