# config helper
import binascii
import hashlib
import os


class ConfigHelper:

    def is_true(self,str):
        return str.lower() in ['true', '1', 't', 'y', 'yes']

    def set_log_level(self, str):
        str=str.upper()
        if str in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            return(str)
        else:
            return("NOTSET")

    def hash_pass(self, password):
        """Hash a password for storing."""
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                      salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash)  # return bytes