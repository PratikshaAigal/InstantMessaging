import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os
import threading
import hashlib

class Client:
    def __init__(self, username, server_host='192.168.1.231', server_port=12346):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.peer_host = None
        self.peer_port = None

    def register(self):
        threading.Thread(target=self.listen_for_messages).start()
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        request = {
            "type": "register",
            "username": self.username,
            "public_key": pem,
            "port": 12347,
            "host": "192.168.1.242"
        }
        response = self.send_request(request)
        print(f"Registration: {response['status']}")

    def write_to_file(self, data):
        """
        Creates a new file if not already present and writes the data to it.
        Appends to the file if it already exists.
        """
        file_name = f"{self.username}_messages.log"
        mode = "a"  # Append mode to add new data without overwriting
        try:
            with open(file_name, mode) as file:
                file.write(data + "\n")
            print(f"Message saved to {file_name}")
        except Exception as e:
            print(f"Error writing to file: {e}")

    def initiate_session(self, target):
        request = {
            "type": "session_request",
            "initiator": self.username,
            "target": target
        }
        response = self.send_request(request)
        if response["status"] == "success":
            print(f"initiate_session")
            encrypted_key = response["session_ticket_initiator"]
            print(f"initiate_session 2")
            self.session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"initiate_session 3", self.session_key)
            self.peer_host, self.peer_port = response["peer_address"]
            print(f"initiate_session 4", response["peer_address"])
            print(f"Session established successfully with {target} {self.peer_host} { self.peer_port}")
            print(f"initiate_session 4")
        else:
            print(f"Session initiation failed: {response['message']}")

    def listen_for_messages(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
            peer_socket.bind(('0.0.0.0', 12347))  # Bind to any free port
            peer_socket.listen(1)
            print(f"Listening for messages on {peer_socket.getsockname()}")
            conn, addr = peer_socket.accept()
            print(f"Connected to {addr}")
            while True:
                encrypted_message = conn.recv(4096)
                self.write_to_file(self, "encrypted_message")
                if not encrypted_message:
                    break
                message = self.decrypt_message(encrypted_message)
                print(f"Message from {addr}: {message}")

    def send_message(self, message):
        print("message sending", message)
        if self.peer_host and self.peer_port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                print("message sending2", type(self.peer_port), type(self.peer_port))
                peer_socket.connect(('192.168.1.242', 12348))
                print("message sending2", message)
                encrypted_message = self.encrypt_message(message)
                print("message sending3", encrypted_message)
                peer_socket.send(encrypted_message)
                print("Message sent.")
        else:
            print("No active session.")

    def encrypt_message(self, plaintext):
        stream = self.generate_stream(len(plaintext))
        encrypted_message = bytes([b ^ s for b, s in zip(plaintext.encode(), stream)])
        return encrypted_message

    def decrypt_message(self, ciphertext):
        self.write_to_file(self, "decrypt_message")
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
