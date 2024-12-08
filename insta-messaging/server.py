import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os
import pickle
import base64
import sqlite3
from contextlib import closing

class Server:
    def __init__(self, host='127.0.0.1', port=4000):
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
            elif request["type"] == "list_clients":
                self.list_clients(client_socket)
            # Add more request handlers as needed
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()

    def list_clients(self, conn):
        client_list = list(self.clients.keys())  # Retrieve usernames of all registered clients
        response = {"status": "success", "clients": client_list}
        conn.send(pickle.dumps(response))
        print("Sent list of clients.")

    def register_client(self, client_socket, request):
        username = request["username"]
        public_key_base64 = request["public_key"]
        client_address = client_socket.getpeername()
        listen_port = request["listen_port"]
        address_str = f"{client_address[0]}:{listen_port}"

        # Convert base64 back to PEM
        public_key_pem = base64.b64decode(public_key_base64).decode('utf-8')
        # Load the public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        with self.lock:
            if username not in self.clients:
                self.clients[username] = {
                    "public_key": public_key,
                    "state": "idle",
                    "address": address_str
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
                    "session_ticket_target": session_ticket_target,
                    "peer_address": self.clients[target]["address"]
                }
            else:
                response = {"status": "error", "message": "Target is not idle"}
        client_socket.send(pickle.dumps(response))

if __name__ == "__main__":
    server = Server()
    server.start()
