from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Save the private key to a file
    with open(private_key_file, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Extract and save the public key to a file
    public_key = private_key.public_key()
    with open(public_key_file, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Keys saved: {private_key_file}, {public_key_file}")

    return private_key

if __name__ == "__main__":
    private_key_file = input("Enter private key file name ")
    pub_key_file = input("Enter public file name ")
    # Generate and save the keys
    generate_rsa_keypair(private_key_file,pub_key_file)
