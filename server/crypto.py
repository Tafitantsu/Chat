import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode

# For now, we'll use a fixed key. In a real application, this would be generated
# securely and shared between client and server.
FIXED_KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes for AES-256

def generate_key():
    """
    Generates a new AES key.
    In a real application, this key would need to be securely shared.
    For this project, we might use a predefined key or a simple derivation.
    """
    # For now, returning the fixed key.
    # In a later step, we can explore more secure key exchange/management.
    return FIXED_KEY

def encrypt_message(key, plaintext):
    """
    Encrypts a message using AES (CBC mode) with PKCS7 padding.
    """
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('utf-8')

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Prepend IV to ciphertext for use in decryption
    return urlsafe_b64encode(iv + ciphertext)

def decrypt_message(key, encoded_ciphertext):
    """
    Decrypts a message using AES (CBC mode) with PKCS7 padding.
    Expects the IV to be prepended to the ciphertext.
    """
    ciphertext_with_iv = urlsafe_b64decode(encoded_ciphertext)
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')
