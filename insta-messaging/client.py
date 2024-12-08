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
import random
import time

# ANSI escape codes for centering text
LEFT_INDENT = "\x1b[1m\x1b[32m"  # Bold green for left
RIGHT_INDENT = "\x1b[36m"  # Cyan for right
RESET = "\x1b[0m"  # Reset formatting

def format_chatbot_text_left(text, width=100):
    left_padding = (width - len(text)) // 2
    right_padding = width - len(text) - left_padding
    return f"{LEFT_INDENT}{' ' * left_padding}{text}{' ' * right_padding}{RESET}"

def format_chatbot_text_right(text, width=100):
    right_padding = (width - len(text)) // 2
    left_padding = width - len(text) - right_padding
    return f"{RIGHT_INDENT}{text}{' ' * right_padding}{RESET}"

class Client:
    def __init__(self, username, server_host='127.0.0.1', server_port=4000):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.peer_host = None
        self.peer_port = None

        # Create and bind a single socket for both listening
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.server_host, 0))  # Bind to any available port
        self.listen_port = self.socket.getsockname()[1]
        self.session_active = False





    def register(self):
        # Convert public key to PEM format and base64 encode it
        public_key_pem = self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        public_key_base64 = base64.b64encode(public_key_pem).decode('utf-8')

        request = {
            "type": "register",
            "username": self.username,
            "public_key": public_key_base64,
            "listen_port": self.listen_port,  # Send listening port to the server
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
            ticket_to_target = response["session_ticket_target"]
            self.session_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            # Update peer host and listening port
            self.peer_host, self.peer_port = response["peer_address"].split(":")
            self.peer_port = int(self.peer_port)

            peer_socket = self.forward_ticket_to_target(ticket_to_target, target)
            return peer_socket
            print(f"Session established successfully with {target}")
            # threading.Thread(target=self.listen_for_messages).start()
        else:
            print(f"Session initiation failed: {response['message']}")

    def forward_ticket_to_target(self, ticket_to_target, target_user):
        """Send the session ticket to the target client."""
        try:
            # Assuming the server maintains information about target clients' address/port
            # target_address = (self.peer_host, self.peer_port)
            # self.socket.connect(target_address)
            request_body = {
                "type": "forward_ticket",
                "target": target_user,
                "ticket": ticket_to_target,
                "listening_port": self.listen_port,
                "user": self.username
            }
            response, peer_socket = self.connect_to_peer(request_body)
            if response["status"] == "success":
                print(f"Ticket forwarded to {target_user} successfully.")
                return peer_socket
        except Exception as e:
            print(f"Failed to forward ticket to {target_user}: {e}")

    def listen_for_messages(self):
        """Continuously listen for incoming connections and messages."""
        self.socket.listen(1)  # Allow only 1 connection at a time
        print(f"Listening for connections and messages on {self.socket.getsockname()}")

        while True:
            client_soc, addr = self.socket.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=self.handle_client_connection, args=(client_soc, addr)).start()


    def handle_client_connection(self, peer_socket, addr):
        """Handle a client connection."""
        try:
            # First ticket should always contain a ticket if not refuse connection
            data = peer_socket.recv(4096)
            if not data:
                print(f"Connection closed by {addr}")
                return

            request = pickle.loads(data)
            sender = request["user"]

            if request["type"] == "forward_ticket":
                # Handle ticket forwarding
                print(f"Received ticket from {addr}")

                # If ticket is verified enter the chat
                if self.process_ticket(request, peer_socket, addr):
                    # Start threads for receiving and sending messages
                    print(f"Session active with {sender} ({self.peer_host}:{self.peer_port}). (Enter your message or press 9 to exit)")
                    print("Please press 0 to continue")
                    self.session_active = True

                    receive_thread = threading.Thread(target=self.receive_messages, args=(peer_socket, sender))
                    send_thread = threading.Thread(target=self.send_messages, args=(peer_socket,))
                    receive_thread.start()
                    send_thread.start()

                    # Wait for both threads to finish before allowing the user to start another session
                    receive_thread.join()
                    send_thread.join()
        except Exception as e:
            print(f"Error handling connection from {addr}: {e}")
        finally:
            peer_socket.close()
            self.session_active = False


    def process_ticket(self, request, peer_socket, addr):
        """Process the session ticket sent by the initiator."""
        try:
            ticket = request["ticket"]
            self.session_key = self.private_key.decrypt(
                ticket,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            # Update the addr as its peer addr as peer address
            self.peer_host = addr[0]
            self.peer_port = request["listening_port"]
            print(f"Session established with {addr}.")
            peer_socket.send(pickle.dumps({"status":"success"}))
            return True
        except Exception as e:
            print(f"Failed to process session ticket: {e}")
            return False



    def close_connection(self, peer_socket):
        """Close the current session and clean up resources."""
        if self.session_key:
            print("Closing current session...")
            self.session_key = None
            self.peer_host = None
            self.peer_port = None
            if peer_socket:
                peer_socket.close()
            self.session_active = False
            print("Session closed.")
        else:
            print("No active session to close.")





    def send_request(self, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.server_host, self.server_port))
            client_socket.send(pickle.dumps(request))
            response = client_socket.recv(4096)
        return pickle.loads(response)

    def connect_to_peer(self, req):
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.connect((self.peer_host, self.peer_port))
        peer_socket.send(pickle.dumps(req))
        res = peer_socket.recv(4096)
        return pickle.loads(res), peer_socket

    # def send_message(self, message):
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    #         if self.peer_host and self.peer_port:
    #             client_socket.connect((self.peer_host, self.peer_port))
    #             encrypted_message = encrypted_message_with_iv(self.session_key, message)
    #             client_socket.send(encrypted_message)
    #             print("Message sent.")
    #         else:
    #             print("No active session.")

    def send_message(self, message, socket):
        try:
            encrypted_message = encrypted_message_with_iv(self.session_key, message)
            socket.send(encrypted_message)
        except Exception as e:
            print(f"Failed to send the message: {e}")



    # def enter_chat_session(self):
    #     """Handle sending messages while continuously listening for incoming ones."""
    #     print(f"Session active with {self.peer_host}:{self.peer_port}.")
    #     send_thread = threading.Thread(target=self.enter_chat, daemon=True)
    #     send_thread.start()
    #
    #     while send_thread.is_alive():
    #         # Main thread can perform other tasks or just wait
    #         send_thread.join(timeout=0.1)

    def send_messages(self, peer_socket):
        """Threaded method to handle sending messages."""
        # print("Enter your message or press 9 to exit the chat")
        while True:
            # message = input("\nEnter your message or press 0 to exit the chat: ")
            message = input()
            self.send_message(message.strip().encode('utf-8'),peer_socket)
            formatted_text = format_chatbot_text_right(f"{self.username}:" + message)
            print(f"|{formatted_text}|")

            if message == "9":
                self.close_connection(peer_socket)
                print("Session terminated.")
                break


    def receive_messages(self, peer_socket, sender):
        while True:
            try:
                encrypted_message = peer_socket.recv(1024)
                message = decrypt_message_with_iv(self.session_key, encrypted_message).decode('utf-8')
                if message == '0':
                    print("Connection closed by the other client.")
                    break
                # print(f"\n{sender}: {message}")
                formatted_text = format_chatbot_text_left(f"{sender}: {message}")
                print(f"|{formatted_text}|")
            except Exception as e:
                print(f"Error listening to messages {e}")
                break
        self.close_connection(peer_socket)

    def start_session(self):
        target = input("Enter the username of the client to initiate a session with: ")
        peer_socket = self.initiate_session(target)

        if not self.session_key:
            print("Session initiation failed. Try again or select another option.")
            return
        else:
            # Start threads for receiving and sending messages
            print(f"Session active with {target} ({self.peer_host}:{self.peer_port}). (Enter your message or press 9 to exit)")

            receive_thread = threading.Thread(target=self.receive_messages, args=(peer_socket, target))
            send_thread = threading.Thread(target=self.send_messages, args=(peer_socket,))
            receive_thread.start()
            send_thread.start()

            # Wait for both threads to finish before allowing the user to start another session
            receive_thread.join()
            send_thread.join()


# def get_random_open_port():
#     while True:
#         port = random.randint(49152, 65535)
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#             if s.connect_ex(('localhost', port)) != 0:  # Port is not in use
#                 return port


if __name__ == "__main__":
    username = input("Enter your username: ")
    client = Client(username)

    # Register the client to the server
    client.register()

    # Start a thread to listen for incoming messages
    listening_thread = threading.Thread(target=client.listen_for_messages, daemon=True)
    listening_thread.start()

    time.sleep(2)

    # Start the main thread
    while True:
        # If a session is active, go to sleep
        print("\n--- Menu ---")
        print("1. Start a new session")
        print("2. List available clients")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            client.start_session()
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
            print("Exiting...")
            break

        else:
            if choice != "0":
                print("Invalid choice. Please try again.")
            if client.session_active:
                client.old_message = choice # This is the message to send to user not a menu choice
                while client.session_active:
                    # print("Session active. Going to sleep until the session is closed...")
                    time.sleep(5)


        time.sleep(3)

