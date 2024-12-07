import hashlib
from typing import Generator
import secrets

# Generate 12 secure random bytes for the IV
def generate_iv():
    return secrets.token_bytes(12)


def stream_cipher_keyed_hash(key: bytes, nonce: bytes, length: int) -> Generator[int, None, None]:
    """
    Generate a stream of pseudo-random bytes using a keyed hash function (SHA-256).
    Args:
        key (bytes): Symmetric key for the hash.
        nonce (bytes): Initialization vector (IV) for the hash.
        length (int): Number of bytes to generate.

    Yields:
        int: Byte from the pseudo-random stream.
    """
    counter = 0
    while length > 0:
        # Combine the key, nonce, and counter into a single input.
        input_data = key + nonce + counter.to_bytes(4, 'big')
        # Hash the input data.
        hash_output = hashlib.sha256(input_data).digest()
        # Yield bytes from the hash output until length is satisfied.
        for byte in hash_output:
            yield byte
            length -= 1
            if length <= 0:
                break
        counter += 1

def encrypt_stream_cipher(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using a stream cipher based on keyed hash.
    Args:
        key (bytes): Symmetric key for the hash.
        nonce (bytes): Initialization vector.
        plaintext (bytes): Plaintext to encrypt.

    Returns:
        bytes: Ciphertext with the IV prepended.
    """
    stream = stream_cipher_keyed_hash(key, nonce, len(plaintext))
    ciphertext = bytes([pt_byte ^ next(stream) for pt_byte in plaintext])

    return ciphertext

def decrypt_message_with_iv(key: bytes, iv_ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using a stream cipher based on keyed hash.
    Args:
        key (bytes): Symmetric key for the hash.
        iv_ciphertext (bytes): Ciphertext which includes the IV prepended.

    Returns:
        bytes: Decrypted plaintext.
    """
    # Extract the IV from the ciphertext
    nonce, ciphertext = iv_ciphertext[:12], iv_ciphertext[12:]
    return encrypt_stream_cipher(key, nonce, ciphertext)  # Same operation for stream ciphers.

def encrypted_message_with_iv(key: bytes, plaintext: bytes) -> bytes:
    # Generate a random nonce for each session
    iv = generate_iv()

    encrypted_message = encrypt_stream_cipher(key, iv, plaintext)

    # Add the iv to encrypted message
    iv_encrypted_message = iv + encrypted_message

    return iv_encrypted_message





# Example Usage
if __name__ == "__main__":
    symmetric_key = b'securekey1234567'  # 16-byte symmetric key
    # Generate 16 secure random bytes for nonce
    iv = generate_iv()
    message = b"Hello, Secure World!"

    # Encrypt the message
    encrypted_message = encrypted_message_with_iv(symmetric_key, iv, message)
    print("Encrypted:", encrypted_message)

    # Decrypt the message
    decrypted_message = decrypt_message_with_iv(symmetric_key, encrypted_message)
    print("Decrypted:", decrypted_message.decode())
