import argparse
import sys
import os
import zlib
import json
import requests
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES


def encrypt(plaintext,passphrase):

    kdf_salt = bytes(os.urandom(8)) # 8 bytes
    kdf_iterations = 100000 # was 10000 before PrivateBin version 1.3
    kdf_keysize = 256 # bits of resulting kdf_key

    backend = default_backend()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=int(kdf_keysize / 8), # 256bit
                     salt=kdf_salt,
                     iterations=kdf_iterations,
                     backend=backend)
    kdf_key = kdf.derive(passphrase)

    paste_blob = b64encode(zlib.compress(plaintext))

    cipher_algo = "aes"
    cipher_mode = "gcm" # was "ccm" before PrivateBin version 1.0
    cipher_iv = bytes(os.urandom(16)) # 128 bit
    cipher_tag_size = 128

    cipher = Cipher(algorithms.AES(kdf_key),
                    modes.GCM(cipher_iv, min_tag_length=16),
                    backend=backend)
    encryptor = cipher.encryptor()

    cipher_text = encryptor.update(paste_blob) + encryptor.finalize()

    cipher_text = cipher_text + encryptor.tag[:16]

    cipher_data = {"iv": b64encode(cipher_iv).decode("utf-8"),
                   "v": 1,
                   "iter": kdf_iterations,
                   "ks": kdf_keysize,
                   "ts": cipher_tag_size,
                   "mode": cipher_mode,
                   "adata": "",
                   "cipher": cipher_algo,
                   "salt": b64encode(kdf_salt).decode("utf-8"),
                   "ct": b64encode(cipher_text).decode("utf-8")}

    #print (json.dumps(cipher_data))
    return cipher_data

def send(cipher_json,passphrase,args):
    paste_url = args.url
    paste_formatter = 'plaintext'
    paste_expire = 86400
    paste_opendicussion = 0
    paste_burn = 0
    
    # json payload
    payload = {'data': json.dumps(cipher_json),
               'expire': paste_expire,
               'formatter': paste_formatter,
               'burnafterreading': paste_burn,
               'opendiscussion': paste_opendicussion}
    # http content type
    headers = {'X-Requested-With': 'JSONHttpRequest'}

    r = requests.post(paste_url,
                      data=payload,
                      headers=headers)
    r.raise_for_status()

    try:
        result = r.json()
    except:
        print('Oops, error: %s' % (r.text))
        sys.exit(1)

    paste_status = result['status']
    if paste_status:
        paste_message = result['message']
        print("Oops, error: %s" % paste_message)
        sys.exit(1)
    paste_id = result['id']
    paste_deletetoken = result['deletetoken']

    print('')
    print('Delete paste  : %s/?pasteid=%s&deletetoken=%s' % (paste_url, paste_id, paste_deletetoken))
    print('Paste         : %s/?%s#%s' % (paste_url, paste_id, passphrase.decode('utf-8')))

def main(args):
    key = bytes(os.urandom(32))
    passphrase = b64encode(key)
    plaintext = args.text.encode('utf-8')

    #print("Main-Passphrase:\t{}".format(passphrase))
    #print("Main-Data      :\t{}".format(plaintext))
    
    cipher_json =encrypt(plaintext,key)

    #print(cipher_json)
    
    send(cipher_json,passphrase,args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="PrivateBin URL")
    parser.add_argument("-p", "--password", dest="password", default='')
    parser.add_argument("-f", "--file", dest="file",default='')
    parser.add_argument("-v", "--verbose", dest="verbose", action="count",
                        default=0, help="Verbosity (-v, -vv, etc)")
    parser.add_argument(dest='text',help="Text to send")
    arguments = parser.parse_args()
    sys.exit(main(arguments))
    
