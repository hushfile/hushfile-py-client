hushfile-py-client
==================
A commandline client for hushfile written in python.


API support
===========
This client currently only works with the server running on https://dev.hushfile.it/ until 
the new API is stable and the new server is in production. To make the script use the dev 
server simply put the .hushfilerc config file in the homedir.


Requirements
============
The python hushfile client makes use of the following python packages:
- requests
- pycrypto

To get SNI support for the https client (neccesary for use with the current https://hushfile.it service!) the following additional modules are neccesary:
- pyOpenSSL
- ndg-httpsclient
- pyasn1


Usage
=====
    $ ./hushfile /COPYRIGHT
    https://dev.hushfile.it/e4551d36624e54655684d15bc15c04#-mU_SfX-A0-I7-Q_6XfZ6aF1z9-Ry8t6J-7H0I1n3
    $ ./hushfile https://dev.hushfile.it/e4551d36624e54655684d15bc15c04#-mU_SfX-A0-I7-Q_6XfZ6aF1z9-Ry8t6J-7H0I1n3
    wrote file to COPYRIGHT
    $ md5 /COPYRIGHT
    MD5 (/COPYRIGHT) = 976e1daf4a0bb3b491112a0721b403f1
    $ md5 COPYRIGHT
    MD5 (COPYRIGHT) = 4e23c67d4fad3a94c84cdf4a0e173121
    $
