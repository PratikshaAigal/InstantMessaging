import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import pickle
from cryptography.hazmat.primitives import serialization

class Server:
    def __init__(self, host='0.0.0.0', port=12346):
        print("hello")
        self.host = host
        self.port = port
        self.clients = {}  # Stores client states and public keys
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()
        self.start()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server running on {self.host}:{self.port}")
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        print("No data received.")
        try:
            data = client_socket.recv(4096)
            print("data is ", data)
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
        public_pem_key = request["public_key"]
        peer_host = request["host"]
        peer_port = request["port"]
        print("client request", request)
        with self.lock:
            public_key = serialization.load_pem_public_key(public_pem_key)
            if username not in self.clients:
                self.clients[username] = {
                    "public_key": public_key,
                    "state": "idle",
                    "peer_port": peer_port,
                    "peer_host": peer_host
                }
                response = {"status": "success"}
            else:
                response = {"status": "error", "message": "Username already exists"}
        client_socket.send(pickle.dumps(response))

    def create_session(self, client_socket, request):
        print("create_session",request)
        initiator = request["initiator"]
        target = request["target"]
        with self.lock:
            if self.clients.get(target, {}).get("state") == "idle":
                print("create_session 2")
                session_key = os.urandom(32)  # Generate a secure session key
                initiator_key = self.clients[initiator]["public_key"]
                target_key = self.clients[target]["public_key"]
                peer_port = self.clients[target]["peer_port"]
                peer_host = self.clients[target]["peer_host"]
                print("create_session 2.5",self.clients[target])
                session_ticket_initiator = initiator_key.encrypt(
                    session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                print("create_session 3")
                session_ticket_target = target_key.encrypt(
                    session_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                print("create_session 4")
                self.clients[initiator]["state"] = "busy"
                self.clients[target]["state"] = "busy"
                response = {
                    "status": "success",
                    "session_ticket_initiator": session_ticket_initiator,
                    "session_ticket_target": session_ticket_target,
                    "peer_address": {
                        "peer_port": peer_port,
                        "peer_host": peer_host
                    }
                }
            else:
                response = {"status": "error", "message": "Target is not idle"}
        print("create_session 5")
        client_socket.send(pickle.dumps(response))


# Add this block at the bottom of your file
if __name__ == "__main__":
    print("Starting server...")
    server = Server()