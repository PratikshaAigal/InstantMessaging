import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os
import threading
import hashlib
from crypto import decrypt_message_with_iv, encrypted_message_with_iv
import base64

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
        # Convert public key to PEM format and base64 encode it
        public_key_pem = self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        public_key_base64 = base64.b64encode(public_key_pem).decode('utf-8')

        request = {
            "type": "register",
            "username": self.username,
            "public_key": public_key_base64
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
            self.peer_host, self.peer_port = response["peer_address"].split(":")
            self.peer_port = int(self.peer_port)

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
                message = decrypt_message_with_iv(self.session_key, encrypted_message)
                print(f"Message from {addr}: {message}")

    def send_message(self, message):
        if self.peer_host and self.peer_port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                peer_socket.connect((self.peer_host, self.peer_port))
                encrypted_message = encrypted_message_with_iv(self.session_key, message)
                peer_socket.send(encrypted_message)
                print("Message sent.")
        else:
            print("No active session.")

    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.server_host, self.server_port))
            client_socket.send(pickle.dumps(request))
            response = client_socket.recv(4096)
        return pickle.loads(response)


if __name__ == "__main__":
    username = input("Enter your username: ")
    client = Client(username)

    # Register the client to the server
    client.register()

    while True:
        print("\n--- Menu ---")
        print("1. Start a new session")
        print("2. List available clients")
        print("3. Show current session status")
        print("4. Send a message in the current session")
        print("5. Terminate the current session")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            if client.session_key:
                print("You are already in a session. Terminate the current session to start a new one.")
            else:
                target = input("Enter the username of the client to initiate a session with: ")
                client.initiate_session(target)

        elif choice == "2":
            request = {"type": "list_clients"}
            response = client.send_request(request)
            if response["status"] == "success":
                print("Available clients:")
                for client_name in response["clients"]:
                    print(f" - {client_name}")
            else:
                print("Failed to fetch the list of clients.")

        elif choice == "3":
            if client.session_key:
                print(f"Current session with: {client.peer_host}:{client.peer_port}")
            else:
                print("No active session.")

        elif choice == "4":
            if client.session_key:
                message = input("Enter your message: ")
                client.send_message(message.encode('utf-8'))
            else:
                print("No active session. Start a session first.")

        elif choice == "5":
            if client.session_key:
                print("Terminating current session...")
                client.session_key = None
                client.peer_host = None
                client.peer_port = None
                print("Session terminated.")
            else:
                print("No active session to terminate.")

        elif choice == "6":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")
