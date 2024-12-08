from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(data, public_key):
    """
    Encrypts data using RSA (for small messages).
    Args:
        data: The plaintext data to encrypt.
        public_key: The RSA public key in PEM format.
    Returns:
        The encrypted data as bytes.
    """
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

def decrypt_with_rsa(data, private_key):
    """
    Decrypts data using RSA.
    Args:
        data: The encrypted data as bytes.
        private_key: The RSA private key in PEM format.
    Returns:
        The decrypted plaintext data.
    """
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(data)

def encrypt_with_aes(data, key):
    """
    Encrypts data using AES (symmetric encryption).
    Args:
        data: The plaintext data to encrypt.
        key: The AES key.
    Returns:
        A tuple of (encrypted data, IV).
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return ciphertext, cipher.iv

def decrypt_with_aes(ciphertext, key, iv):
    """
    Decrypts data using AES.
    Args:
        ciphertext: The encrypted data.
        key: The AES key.
        iv: The initialization vector (IV).
    Returns:
        The decrypted plaintext data.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def create_hmac(message, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message.encode())
    return h.digest()

def verify_hmac(message, hmac_to_verify, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message.encode())
    try:
        h.verify(hmac_to_verify)
        return True
    except ValueError:
        return False
