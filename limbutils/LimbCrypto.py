# Class that Handles Limb Cryptography for the Server

from limbutils.limbserverlib.LimbLogger import LimbLogger
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from Crypto.Cipher import AES
from hashlib import sha256
from os import urandom

class LimbCrypto:
    EXPONENT = 65537
    
    logger : LimbLogger

    privkeyfile : str

    pubkeyfile : str

    # Initializes the Object with Logging Capabilities and Specifying where the public and private keys are to be stored
    def __init__(self, privkeyfile : str, pubkeyfile : str, limbLogger : LimbLogger = None):
        self.logger = limbLogger
        self.pubkeyfile = pubkeyfile
        self.privkeyfile = privkeyfile
    
    # A Method that returns an RSA Public Key Object from the RSA public key file specified to the object on initialization
    def getPubKey(self) -> _RSAPublicKey:
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

    # A Method that returns PEM formatted bytes for the key file given to the object on initialization
    def getPubKeyBytes(self) -> bytes:
        return self.getPubKey().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # A Method that takes in PEM formatted RSA public key bytes and returns a public key object
    def decodePubKeyBytes(self, pubkeybytes : bytes) -> _RSAPublicKey:
        return serialization.load_pem_public_key(pubkeybytes)

    # A Method that returns a PrivateKey Object from the file given to the object on initialization
    def getPrivKey(self) -> _RSAPrivateKey:
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

    # A Method that Decrypts Data of Any Length by Breaking it into segments with a Specified Key. If no Key is Specified, the Class defined Key is used.
    def decryptData(self, binarydata: bytes, key: _RSAPrivateKey = None) -> bytes:
        if len(binarydata) % 256 != 0:
            if self.logger: self.logger.registerEvent("ERROR", "Decryption of Data Failed due to Improper Data")
        num_segments = int(len(binarydata) / 256)
        data = binarydata
        decrypted_data = bytes()
        for i in range(num_segments):
            current_segment = data[0:256]
            data = data[256:]
            decrypted_data += self._decryptSmallData(current_segment, key)
        return decrypted_data

    # A method that Decrypts small segments of data (256 Bytes) using the key specified (or the class key if none specified)
    def _decryptSmallData(self, binarydata: bytes, key : _RSAPrivateKey= None) -> bytes:
        if key == None:
            private_key = self.getPrivKey()
        else:
            private_key = key
        return private_key.decrypt(
            binarydata,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
        )
    )

    # A Method that Signs Small Data Segments using the RSA library. May be any size, as it implements hashing
    def signSmallData(self, smalldata : bytes, private_key : _RSAPrivateKey = None) -> bytes:
        if private_key == None:
            private_key = self.getPrivKey()
        return private_key.sign(smalldata,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), hashes.SHA256()
        )

    # A Method that Verifies an RSA generated Signature for a piece of data. Returns a boolean value that states whether the signature was verified or not.
    def verifySignatureData(self, message : bytes, signature : bytes, public_key : _RSAPublicKey = None) -> bool:
        try:
            pubkey = public_key
            if pubkey == None:
                pubkey = self.getPubKey()
            pubkey.verify(signature, message,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ), hashes.SHA256())
            return True
        except:
            return False

    # A Method that Encrypts Data of Any Length by Breaking it into segments with a Specified Key. If no Key is Specified, the Class defined Key is used.
    def encryptData(self,binarydata : bytes, key : _RSAPublicKey = None) -> bytes:
        binarylen = len(binarydata)
        data = binarydata
        encryptedData = bytes()
        while binarylen > 0:
            segmentlength = min(binarylen, 190)
            binarylen -= segmentlength
            datasegment = data[0:segmentlength]
            data = data[segmentlength:]
            encryptedData += self._encryptSmallData(datasegment, key)
        return encryptedData

    # A method that Encrypts small segments of data (<190 bytes) using the key specified (or the class key if none specified)
    def _encryptSmallData(self, binarydata : bytes, key : _RSAPublicKey = None) -> bytes:
        if key == None:
            public_key = self.getPubKey() 
        else:
            public_key = key
        return public_key.encrypt(
            binarydata,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
            )

    # A method that Generates a 2048 bit RSA keypair to be stored in the files specified by your TOML configuration
    def generateKeyPair(self) -> None: 
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

        if self.logger: self.logger.registerEvent("KGEN", f"Public and Private RSA Keys Generated at {self.pubkeyfile} and {self.privkeyfile}")

    # A function that Encrypts a given set of bytes with AES encryption using a supplied key and initial vector
    def aes_encrypt(inputbytes : bytes, key : bytes, ivseed : bytes) -> bytes:
        aes_obj = AES.new(key, AES.MODE_CFB, LimbCrypto.calculate_aes_iv(ivseed))
        return aes_obj.encrypt(inputbytes)

    # A function that Decrypts a given set of bytes with AES encryption using a supplied key and initial vector
    def aes_encrypt(inputbytes : bytes, key : bytes, ivseed : bytes) -> bytes:
        aes_obj = AES.new(key, AES.MODE_CFB, LimbCrypto.calculate_aes_iv(ivseed))
        return aes_obj.decrypt(inputbytes)

    # Calculates an Initial Vector to Protect the Key Given Some bytes input
    def calculate_aes_iv(input : bytes) -> bytes:
        return sha256(input).digest()[0:16]

    # Generates a 16B AES Key
    def generate_aes_key() -> bytes:
        return urandom(16)