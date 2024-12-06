import json
import unittest
from modules.cryptographer import PublicCryptographer, PrivateCryptographer
from cryptography.exceptions import InvalidTag


class CryptoTest(unittest.TestCase):

    def setUp(self):
        public_key = "keys/id_test_rsa.pub"
        private_key = "keys/id_test_rsa"
        public_key_pem = "keys/id_test_rsa_public.pem"

        self.pub_crypt = PublicCryptographer(public_key)
        self.private_crypt = PrivateCryptographer(public_key_pem, private_key, b'snuggles')

        # Create a dictionary with test user data, including name, age, and email.
        self.test_data = {
            "name": "John Doe",
            "age": 30,
            "email": "jd@holy.cow"
        }

        return super().setUp()

    def testCryptoCycle(self):

        test_data_str = json.dumps(self.test_data)

        aes_key = self.pub_crypt.generate_aes_key()
        rsa = self.pub_crypt.rsa_encrypt(aes_key)
        iv, encrypted_data, auth_tag = self.pub_crypt.aes_encrypt(test_data_str, aes_key)

        data_str = self.private_crypt.aes_decrypt(encrypted_data, aes_key, iv, auth_tag)
        self.assertEqual(data_str, test_data_str)

        self.assertEqual(aes_key, self.private_crypt.rsa_decrypt(rsa))

    def testCryptoCycleUserData(self):

        test_data_str = json.dumps(self.test_data)

        aes_key = self.pub_crypt.generate_aes_key()
        rsa = self.pub_crypt.rsa_encrypt(aes_key)
        iv, encrypted_data, auth_tag = self.pub_crypt.aes_encrypt(test_data_str, aes_key)

        data_str = self.private_crypt.aes_decrypt(encrypted_data, aes_key, iv, auth_tag)
        self.assertEqual(data_str, test_data_str)

        self.assertEqual(aes_key, self.private_crypt.rsa_decrypt(rsa))

        add_data = "bunny ruvs pooh"
        iv, encrypted_data, auth_tag = self.pub_crypt.aes_encrypt(test_data_str, aes_key, add_data)

        data_str = self.private_crypt.aes_decrypt(encrypted_data, aes_key, iv, auth_tag, add_data)
        self.assertEqual(data_str, test_data_str)

        add_data = "pooh ruvs bunny"
        with self.assertRaises(InvalidTag):
            data_str = self.private_crypt.aes_decrypt(encrypted_data, aes_key, iv, auth_tag, add_data)
            self.assertEqual(data_str, test_data_str)
