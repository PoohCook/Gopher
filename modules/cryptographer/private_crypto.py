from pprint import pprint
from cryptography.hazmat.primitives.ciphers import Cipher as CCipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

import os
import base64


class PrivateCryptographer:

    rsa_public_key = None
    rsa_private_key = None

    def __init__(self, public_key, private_key, password):
        #Read key from file
        with open(public_key, "r") as file:
          pub_key_str = file.read()

        pprint(type(pub_key_str))
        self.rsa_public_key = load_pem_public_key(bytes(pub_key_str, 'utf-8'), backend=default_backend())
        self.__check_initialized()

        if private_key:
            #Read key from file
            with open(private_key, "r") as file:
              private_key_str = file.read()

            self.rsa_private_key = load_pem_private_key(bytes(private_key_str, 'utf-8'),
                                                        backend=default_backend(), password=password)
            assert isinstance(self.rsa_private_key, rsa.RSAPrivateKey)

    def __check_initialized(self):
        assert isinstance(self.rsa_public_key, rsa.RSAPublicKey)

    def generate_aes_key(self):
        return os.urandom(32)

    def aes_encrypt(self, data, key, associated_data=''):
        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = CCipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data.encode())

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

        return (base64.urlsafe_b64encode(iv).decode("UTF-8"),
                base64.urlsafe_b64encode(ciphertext).decode("UTF-8"),
                base64.urlsafe_b64encode(encryptor.tag).decode("UTF-8"))

    def aes_decrypt(self, encrypted_data, key, iv, auth_tag, associated_data=''):
        # decode the IV
        iv = base64.urlsafe_b64decode(iv)
        tag = base64.urlsafe_b64decode(auth_tag)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        decryptor = CCipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        decryptor.authenticate_additional_data(associated_data.encode())

        # decode the ciphertext
        ciphertext = base64.urlsafe_b64decode(encrypted_data.encode())

        # Decrypt the ciphertext and get the associated plaintext.
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode("UTF-8")

    def rsa_encrypt(self, data):
        self.__check_initialized()
        ciphertext = self.rsa_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return base64.urlsafe_b64encode(ciphertext).decode("UTF-8")

    def rsa_decrypt(self, encrypted_data):
        ciphertext = base64.urlsafe_b64decode(encrypted_data)
        data = self.rsa_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return data
