#!/usr/bin/env python
import logging, json, os, sys, requests, mimetypes
from optparse import OptionParser
from random import choice
from hashlib import md5
from Crypto.Cipher import AES

class HushfileUtils:
    """Hushfile utilities class"""
    def mkpassword(minlength=40,maxlength=50):
        """Return a random password"""
        charsets = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            '-_',
        ]
        length=random.randint(minlength,maxlength)
        pwd = []
        charset = choice(charsets)
        while len(pwd) < length:
            pwd.append(choice(charset))
            charset = choice(list(set(charsets) - set([charset])))
        return "".join(pwd)


    def EVP_ByteToKey(password, salt='Salted', key_len=32, iv_len=16):
        """Derive the key and the IV from the given password and salt."""
        dtot =  md5(password + salt).digest()
        d = [ dtot ]
        while len(dtot)<(iv_len+key_len):
            d.append( md5(d[-1] + password + salt).digest() )
            dtot += d[-1]
        return dtot[:key_len], dtot[key_len:key_len+iv_len]


class HushfileApi:
    """Hushfile API client class"""
    
    def __init__(self):
        ### load config from homedir
        config = None
        configpath = os.path.join(os.path.expanduser("~"),'.hushfilerc')
        
        if os.path.exists(configpath):
            with open(configpath) as f:
                config = json.loads(f.read())
            if config is None:
                print ">>> Error reading config, using defaults. Please check %s" % configpath

        if config is None:
            ### no config found, or error reading config, using defaults
            config = {
                'server': 'hushfile.it',
                'deleteable': True,
                'minpwlen': 40,
                'maxpwlen': 50
            }

    def ServerInfo(self):
        """Implements ServerInfo API call"""
        r = requests.get("https://%s/api/serverinfo" % config['server'])
        logger.info("ServerInfo API call reply: %s" % r.json())
        self.serverinfo = r.json()

    def UploadFile(self,filepath):
        ### check filesize
        filesize = os.path.getsize(filepath)
        if filesize > self.serverinfo.max_filesize:
            ### file too large for the server
            logger.error("%s: file too large" % filepath)
            logger.error("server https://%s max_filesize is %s bytes, file is %s bytes" % (self.config['server'], hf.serverinfo.max_filesize, os.path.getsize(filepath)))
            sys.exit(1)
            
        ### decide on chunking
        chunking = True
        
        ### pick a chunksize
        chunksize = 1048576
        
        ### generate password and deletepassword
        password = hfutil.mkpassword(config['minpwlen'],config['maxpwlen'])
        if config['deleteable']:
            deletepassword = hfutil.mkpassword(config['minpwlen'],config['maxpwlen'])
        
        ### find mimetype
        mimetypes.init()
        mimetype = mimetypes.guess_type(filepath)[0]
        if not mimetype:
            ### default mimetype
            mimetype = "application/octet-stream"
        
        ### find filename
        filename = os.path.basename(filepath)
        
        ### generate and encrypt metadata json
        metadatadict = {
            "filename": filename, 
            "mimetype": mimetype, 
            "filesize": os.path.getsize(filepath)
        }

        ### add deletepassword if neccesary
        if config['deleteable']:
            metadatadict['deletepassword'] = deletepassword
        
        ### dump json string
        metadatajson = json.dumps(metadatadict)
        
        ### encrypt metadata
        logger.info("encrypting metadata")
        key, iv = hfutil.EVP_ByteToKey(password)
        aes = AES.new(key, AES.MODE_CBC, iv)
        metadatacrypt = base64.b64encode(aes.encrypt(metadatajson))
        
        ### determine number of chunks
        if chunksize > filesize:
            chunkcount = 1
        else:
            chunkcount = (filesize / chunksize) + 1

        ### read first chunk
        fh = open(filename, 'rb')
        logger.info("reading and encrypting first chunk")
        chunkdata = file.read(chunksize)

        ### encrypt first chunk
        cryptochunk = base64.b64encode(aes.encrypt(chunkdata))
        
        ### prepare to upload the first chunk and the metadata
        payload = {
            'cryptofile': cryptochunk, 
            'metadata': metadatacrypt,
            'chunknumber': 0
        }
        
        ### set finishupload ?
        if chunkcount == 1:
            payload['finishupload'] = True
        
        ### include deletepassword ?
        if config['deleteable']:
            payload['deletepassword'] = deletepassword
        
        ### do the POST
        logger.info("POSTing first chunk and metadata")
        r = requests.post("https://%s/api/upload" % config['server'], data=payload)
        if r.status_code != 200:
            logger.error("error from server: response code %s" % r.status_code)
            sys.exit(1)

        ### get the fileid from the response
        fileid = r.json['fileid']
        
        ### any more chunks ?
        if chunkcount > 1:
            for chunknumber in range(1,chunkcount):
                ### read this chunk
                chunkdata = file.read(chunksize)
                cryptochunk = base64.b64encode(aes.encrypt(chunkdata))
                
                payload = {
                    'fileid': fileid,
                    'cryptofile': cryptochunk, 
                    'chunknumber': chunknumber,
                    'uploadpassword': uploadpassword
                }
                
                ### is this the final chunk ?
                if chunknumber == chunkcount:
                    payload['finishupload'] = True
                else:
                    payload['finishupload'] = False
                
                ### do the POST
                logger.info("POSTing chunk %s of %s" % (chunknumber, chunkcount))
                r = requests.post("https://%s/api/upload" % config['server'], data=payload)
                if r.status_code != 200:
                    logger.error("error from server: response code %s" % r.status_code)
                    sys.exit(1)

        ### done, return the fileid
        self.resulturl = ("https://%s/%s#%s" % (config['server'], fileid, password))
        logger.info("done, url is %s" % self.resulturl)


if __name__ == "__main__":
    ### configure logging
    logging.basicConfig(level=logging.INFO, datefmt='%m-%d %H:%M', format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    logger = logging.getLogger('hushfile')

    ### configure optionparser
    usage = "usage: %prog [options] <path or url>"
    parser = OptionParser(usage=usage)
    (options, args) = parser.parse_args()

    ### initiate hushfile classes
    hf = HushfileApi()
    hfutil = HushfileUtils()

    ### check argument
    if args[0][:8] == 'https://':
        logger.info("%s will be downloaded" % args[0])
        hf.DownloadFile(args[0],args[1])
    else:
        if not os.path.exists(args[0]):
            logger.error("%s: file not found" % args[0])
            sys.exit(1)
        else:
            logger.info("%s will be uploaded" % args[0])
            hf.ServerInfo()
            hf.UploadFile(args[0])
            print hf.resulturl
