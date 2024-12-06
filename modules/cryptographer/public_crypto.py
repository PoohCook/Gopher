import base64
import os
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA

import logging


class PublicCryptographer():

    rsa_public_key = None

    def __init__(self, public_key):
        # Read key from file
        with open(public_key, "r") as file:
            pub_key_str = file.read().strip()
        # Import the public key in PEM format
        self.rsa_public_key = RSA.import_key(pub_key_str)
        self.__check_initialized()

    def __check_initialized(self):
        assert isinstance(self.rsa_public_key, RSA.RsaKey)

    def generate_aes_key(self):
        return os.urandom(32)

    def aes_encrypt(self, data, key, associated_data=''):
        # Create a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
        encryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        if associated_data:
            encryptor.update(associated_data.encode())

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext, tag = encryptor.encrypt_and_digest(data.encode())

        return (base64.urlsafe_b64encode(iv).decode("UTF-8"),
                base64.urlsafe_b64encode(ciphertext).decode("UTF-8"),
                base64.urlsafe_b64encode(tag).decode("UTF-8"))

    def aes_decrypt(self, encrypted_data, key, iv, auth_tag, associated_data=''):
        # decode the IV
        iv = base64.urlsafe_b64decode(iv)
        tag = base64.urlsafe_b64decode(auth_tag)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        decryptor = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        if associated_data:
            decryptor.update(associated_data.encode())
        # decryptor.verify(tag)

        # decode the ciphertext
        ciphertext = base64.urlsafe_b64decode(encrypted_data.encode())

        # Decrypt the ciphertext and get the associated plaintext.
        plaintext = decryptor.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode("UTF-8")

    def rsa_encrypt(self, data):
        self.__check_initialized()
        cipher_rsa = PKCS1_OAEP.new(self.rsa_public_key)
        ciphertext = cipher_rsa.encrypt(data)

        return base64.urlsafe_b64encode(ciphertext).decode("UTF-8")
