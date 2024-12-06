import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import pickle

class Server:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.clients = {}  # Stores client states and public keys
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server running on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            data = client_socket.recv(4096)
            request = pickle.loads(data)
            if request["type"] == "register":
                self.register_client(client_socket, request)
            elif request["type"] == "session_request":
                self.create_session(client_socket, request)
            # Add more request handlers as needed
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

    def register_client(self, client_socket, request):
        username = request["username"]
        public_key = request["public_key"]
        with self.lock:
            if username not in self.clients:
                self.clients[username] = {
                    "public_key": public_key,
                    "state": "idle"
                }
                response = {"status": "success"}
            else:
                response = {"status": "error", "message": "Username already exists"}
        client_socket.send(pickle.dumps(response))

    def create_session(self, client_socket, request):
        initiator = request["initiator"]
        target = request["target"]
        with self.lock:
            if self.clients.get(target, {}).get("state") == "idle":
                session_key = os.urandom(32)  # Generate a secure session key
                initiator_key = self.clients[initiator]["public_key"]
                target_key = self.clients[target]["public_key"]
                session_ticket_initiator = initiator_key.encrypt(
                    session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                session_ticket_target = target_key.encrypt(
                    session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                self.clients[initiator]["state"] = "busy"
                self.clients[target]["state"] = "busy"
                response = {
                    "status": "success",
                    "session_ticket_initiator": session_ticket_initiator,
                    "session_ticket_target": session_ticket_target
                }
            else:
                response = {"status": "error", "message": "Target is not idle"}
        client_socket.send(pickle.dumps(response))
