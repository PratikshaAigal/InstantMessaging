import socket
import threading
from cryptography.hazmat.primitives import serialization
import os
import pickle
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


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
            if request["type"] == "login":
                self.login(client_socket, request)
            if request["type"] == "challenge_reply":
                self.verify_login(client_socket, request)
            elif request["type"] == "session_request":
                self.create_session(client_socket, request)
            elif request["type"] == "list_clients":
                self.list_clients(client_socket)
            elif request["type"] == "close_session":
                self.close_session(client_socket, request)
            elif request["type"] == "logout":
                self.client_logoff(client_socket, request)
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
                    "address": address_str,
                    "active": True
                }
                response = {"status": "success"}
            else:
                response = {"status": "error", "message": "Username already exists"}
        client_socket.send(pickle.dumps(response))

    def login(self, client_socket, request):
        username = request["username"]
        with self.lock:
            if username in self.clients:
                challenge = os.urandom(32)
                # Save the challenge in user data
                self.clients[username]["challenge"] = challenge

                # Send a challenge to client
                response = {"status": "success", "challenge": challenge}

            else:
                response = {"status": "error", "message": "Username does not exists"}
        client_socket.send(pickle.dumps(response))

    def verify_login(self, client_socket, request):
        username = request["username"]
        signed_challenge = request["signed_challenge"]
        client_address = client_socket.getpeername()
        listen_port = request["listen_port"]
        address_str = f"{client_address[0]}:{listen_port}"

        with self.lock:
            if username in self.clients:
                user_public_key = self.clients[username]["public_key"]
                # Verify the signed challenge using the client's public key
                try:
                    user_public_key.verify(
                        signed_challenge,
                        self.clients[username].get("challenge"), #challenge sent
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    self.clients[username]["state"] = 'idle'
                    self.clients[username]["address"] = address_str
                    self.clients[username]["active"] = True
                    res = {"status": "success", "message": "Login successful"}
                except InvalidSignature:
                    res = {"status": "error", "message": "Invalid signature"}
            else:
                res = {"status": "error", "message": "Username does not exists"}

        client_socket.send(pickle.dumps(res))

    def create_session(self, client_socket, request):
        # Fetch data from request body
        initiator = request["initiator"]
        target = request["target"]
        nonce = request["nonce"]

        with self.lock:
            if self.clients.get(target, {}).get("state") == "idle":
                session_key = os.urandom(32)  # Generate a secure session key
                initiator_key = self.clients[initiator]["public_key"]
                target_key = self.clients[target]["public_key"]

                # Genereate tickets to both users and sign them with their respective public keys

                # In the intiator ticket include the session key and their nonce to avoid replay
                initiator_ticket_data = {
                    "session_key": session_key,
                    "nonce": nonce
                }
                serialized_initiator_ticket = pickle.dumps(initiator_ticket_data)
                session_ticket_initiator = initiator_key.encrypt(
                    serialized_initiator_ticket,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

                # In target tickert include the session key, initiator username and their nonce to avoid replay attack
                # Create target ticket with nonce and username embedded
                target_ticket_data = {
                    "session_key": session_key,
                    "initiator": initiator,
                    "nonce": nonce
                }
                serialized_target_ticket = pickle.dumps(target_ticket_data)

                session_ticket_target = target_key.encrypt(
                    serialized_target_ticket,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

                # Update both the client states to busy
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

    def close_session(self, client_socket, request):
        user = request["username"]
        res = {"status": "error"}

        with self.lock:
            self.clients[user]["state"] = "idle"
            res = {"status": "success"}

        client_socket.send(pickle.dumps(res))

    def client_logoff(self, client_socket, request):
        user = request["username"]
        res = {"status": "error"}

        with self.lock:
            self.clients[user]["state"] = "idle"
            self.clients[user]["active"] = False
            res = {"status": "success"}

        client_socket.send(pickle.dumps(res))


if __name__ == "__main__":
    server = Server()
    server.start()
