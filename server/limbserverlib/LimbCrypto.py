# Class that Handles Limb Cryptography for the Server

from limbserverlib.LimbLogger import LimbLogger
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class LimbCrypto:
    EXPONENT = 65537
    
    logger : LimbLogger

    privkeyfile : str

    pubkeyfile : str

    def __init__(self, limbLogger : LimbLogger, privkeyfile : str, pubkeyfile : str):
        self.logger = limbLogger
        self.pubkeyfile = pubkeyfile
        self.privkeyfile = privkeyfile
        
    def getPubKey(self):
        public_key = None 
        try:
            with open(self.pubkeyfile, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                key_file.read())
        except:
            self.generateKeyPair()
        with open(self.pubkeyfile, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                key_file.read())
        return public_key

    def getPrivKey(self):
        private_key = None
        try:
            with open(self.privkeyfile, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(), password = None)
        except:
            self.generateKeyPair()
        with open(self.privkeyfile, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(), password = None)
        return private_key

    def decryptData(self, binarydata):
        private_key = self.getPrivKey()
        return private_key.decrypt(
            binarydata,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
        )
    )

    def encryptData(self, binarydata):
        public_key = self.getPubKey() 
        return public_key.encrypt(
            binarydata,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
            )

    def generateKeyPair(self): 
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        pem_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.pubkeyfile, "wb") as pubfile:
            pubfile.write(pem_public_key)

        with open(self.privkeyfile, "wb") as privfile:
            privfile.write(pem_private_key)

        self.logger.registerEvent("KGEN", f"Public and Private RSA Keys Generated at {self.pubkeyfile} and {self.privkeyfile}")