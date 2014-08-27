hushfile-py-client
==================

A commandline client for hushfile written in python

Requirements
============
The python hushfile client makes use of the following python packages:
- requests
- pycrypto

To get SNI support for the https client (neccesary for use with the current https://hushfile.it service!) the following additional modules are neccesary:
- pyOpenSSL
- ndg-httpsclient
- pyasn1
