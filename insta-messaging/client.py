import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import threading
import hashlib

class Client:
    def __init__(self, username, server_host='127.0.0.1', server_port=12345):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.peer_host = None
        self.peer_port = None

    def register(self):
        request = {
            "type": "register",
            "username": self.username,
            "public_key": self.public_key
        }
        response = self.send_request(request)
        print(f"Registration: {response['status']}")

    def initiate_session(self, target):
        request = {
            "type": "session_request",
            "initiator": self.username,
            "target": target
        }
        response = self.send_request(request)
        if response["status"] == "success":
            encrypted_key = response["session_ticket_initiator"]
            self.session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.peer_host, self.peer_port = response["peer_address"]
            print(f"Session established successfully with {target}")
            threading.Thread(target=self.listen_for_messages).start()
        else:
            print(f"Session initiation failed: {response['message']}")

    def listen_for_messages(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
            peer_socket.bind((self.server_host, 0))  # Bind to any free port
            peer_socket.listen(1)
            print(f"Listening for messages on {peer_socket.getsockname()}")
            conn, addr = peer_socket.accept()
            print(f"Connected to {addr}")
            while True:
                encrypted_message = conn.recv(4096)
                if not encrypted_message:
                    break
                message = self.decrypt_message(encrypted_message)
                print(f"Message from {addr}: {message}")

    def send_message(self, message):
        if self.peer_host and self.peer_port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                peer_socket.connect((self.peer_host, self.peer_port))
                encrypted_message = self.encrypt_message(message)
                peer_socket.send(encrypted_message)
                print("Message sent.")
        else:
            print("No active session.")

    def encrypt_message(self, plaintext):
        stream = self.generate_stream(len(plaintext))
        encrypted_message = bytes([b ^ s for b, s in zip(plaintext.encode(), stream)])
        return encrypted_message

    def decrypt_message(self, ciphertext):
        stream = self.generate_stream(len(ciphertext))
        decrypted_message = bytes([b ^ s for b, s in zip(ciphertext, stream)])
        return decrypted_message.decode()

    def generate_stream(self, length):
        """
        Generate a pseudo-random stream for XOR encryption.
        """
        counter = 0
        stream = b""
        while len(stream) < length:
            hash_input = self.session_key + counter.to_bytes(4, "big")
            stream += hashlib.sha256(hash_input).digest()
            counter += 1
        return stream[:length]

    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.server_host, self.server_port))
            client_socket.send(pickle.dumps(request))
            response = client_socket.recv(4096)
        return pickle.loads(response)
