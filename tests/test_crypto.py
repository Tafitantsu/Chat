import unittest
import sys
import os

# Add the parent directory (SecureChatTCP) to the Python path
# to allow importing modules from the 'client' directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.crypto import generate_key, encrypt_message, decrypt_message

class TestCrypto(unittest.TestCase):

    def test_encrypt_decrypt_string(self):
        key = generate_key()
        original_message = "This is a secret message!"
        encrypted_message = encrypt_message(key, original_message)
        decrypted_message = decrypt_message(key, encrypted_message)
        self.assertEqual(original_message, decrypted_message)

    def test_encrypt_decrypt_empty_string(self):
        key = generate_key()
        original_message = ""
        encrypted_message = encrypt_message(key, original_message)
        decrypted_message = decrypt_message(key, encrypted_message)
        self.assertEqual(original_message, decrypted_message)

    def test_encrypt_decrypt_long_string(self):
        key = generate_key()
        original_message = "This is a very long secret message! " * 100
        encrypted_message = encrypt_message(key, original_message)
        decrypted_message = decrypt_message(key, encrypted_message)
        self.assertEqual(original_message, decrypted_message)

    def test_different_keys_fail_decryption(self):
        key1 = generate_key()
        # Ensure key2 is different if generate_key() could return the same key
        # For now, our generate_key() returns a fixed key, so we manually create a different one.
        key2 = b'anotherkeyanotherkeyanotherkey!!' # Must be 32 bytes
        if key1 == key2: # Should not happen with current fixed key and manual key2
            key2 = b'yet_another_diff_key_32_bytes!'

        original_message = "Test message for different keys."
        encrypted_message = encrypt_message(key1, original_message)

        # Decryption with a different key should ideally raise an error or return incorrect data.
        # The exact behavior depends on the cryptography library and mode of operation.
        # For AES CBC with PKCS7 padding, an incorrect key will likely lead to a padding error
        # or garbage output.
        with self.assertRaises((ValueError, TypeError)): # TypeError for padding, ValueError for other issues
            decrypt_message(key2, encrypted_message)
        # Or, if it doesn't raise an error but returns garbage:
        # decrypted_message_with_wrong_key = decrypt_message(key2, encrypted_message)
        # self.assertNotEqual(original_message, decrypted_message_with_wrong_key)


if __name__ == '__main__':
    unittest.main()
