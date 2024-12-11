import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import threading
from im_crypto import decrypt_message_with_iv, encrypted_message_with_iv
import base64
import time
from generate_keys import generate_rsa_keypair
from cryptography.hazmat.primitives import serialization
import os

# ANSI escape codes for centering text
LEFT_INDENT = "\x1b[1m\x1b[32m"  # Bold green for left
RIGHT_INDENT = "\x1b[36m"  # Cyan for right
RESET = "\x1b[0m"  # Reset formatting


def format_chatbot_text_left(text, width=100):
    """
        Format text for left-aligned chatbot messages.
    """
    left_padding = (width - len(text)) // 2
    right_padding = width - len(text) - left_padding
    return f"{LEFT_INDENT}{' ' * left_padding}{text}{' ' * right_padding}{RESET}"


def format_chatbot_text_right(text, width=100):
    """
        Format text for right-aligned chatbot messages.
    """
    right_padding = (width - len(text)) // 2
    left_padding = width - len(text) - right_padding
    return f"{RIGHT_INDENT}{text}{' ' * right_padding}{RESET}"

def generate_nonce(length=16):
    # Generate a secure random nonce
    return os.urandom(length).hex()  # Hex-encoded nonce for transmission

def decrement_nonce(nonce_hex: str) -> str:
    """
    Decrement a nonce represented as a hex string.
    """
    nonce = int(nonce_hex, 16) - 1
    return format(nonce, 'x')

class Client:
    def __init__(self, username, private_key, server_host='127.0.0.1', server_port=4000,
                 private_key_file="private_key.pem"):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        # Load RSA keys
        self.private_key = private_key
        self.public_key = self.private_key.public_key()

        self.session_key = None
        self.peer_host = None
        self.peer_port = None

        # Create and bind a single socket for both listening
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.server_host, 0))  # Bind to any available port
        self.listen_port = self.socket.getsockname()[1] # Save the port to share with other clients
        self.session_active = False

        # Shared variables for thread handling 
        self.stop_event = threading.Event()

    def register(self):
        """
        Register the user with the server by sending:
        - Public key (Base64-encoded)
        - Listening port
        """
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
        if response['status'] != 'success':
            print(f"{response['message']}, Please try again.")
            return False

        return True

    def login(self):
        """
            Login to the server by responding to a cryptographic challenge.
        """
        # Prepare the login request
        request = {
            "type": "login",
            "username": self.username,
        }
        response = self.send_request(request)

        if response['status'] == 'success':
            challenge = response['challenge']

            # Sign the challenge using the private key
            try:
                signed_challenge = self.private_key.sign(
                    challenge,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                # Send the encyrpted challenge back to the server
                challenge_req = {
                    "type": "challenge_reply",
                    "username": self.username,
                    "signed_challenge": signed_challenge,
                    "listen_port": self.listen_port  # Can change
                }
                response2 = self.send_request(challenge_req)

                if response2['status'] == 'success':
                    return True  # Login successful
                else:
                    print(f"Error: {response2['message']}")
            except Exception as e:
                print(f"Error decrypting the challenge: {e}")
        else:
            print(f"Error: {response['message']}")
        return False  # Login failed

    def initiate_session(self, target):
        """
            Initiate a secure session with another client.
        """
        # Send session request to server
        nonce = generate_nonce() # Include nonce to for freshness
        request = {
            "type": "session_request",
            "initiator": self.username,
            "target": target,
            "nonce": nonce
        }
        response = self.send_request(request)
        if response["status"] == "success":
            ticket_for_me = response["session_ticket_initiator"]
            ticket_to_target = response["session_ticket_target"]

            # Decrypt the ticket
            decrypted_ticket = self.private_key.decrypt(
                ticket_for_me,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Deserialize the ticket to extract its contents
            ticket_data = pickle.loads(decrypted_ticket)
            self.session_key = ticket_data.get("session_key") # session key
            nonce_rcvd = ticket_data.get("nonce") # nonce sent by server to verify itself

            if nonce_rcvd != nonce:
                print("Nonce dont match, server potentially compromised!, Exiting...")
                exit()

            # Update peer host and listening port
            self.peer_host, self.peer_port = response["peer_address"].split(":")
            self.peer_port = int(self.peer_port)

            # Forward the targets ticket and return the socket if connection established
            peer_socket = self.forward_ticket_to_target(ticket_to_target, target, nonce)
            return peer_socket

        else:
            print(f"Session initiation failed: {response['message']}")

    def close_session(self):
        """
            Close the session and notify the server
        """
        # Send request type close_session with username
        request = {
            "type": "close_session",
            "username": self.username,
        }
        response = self.send_request(request)
        if response['status'] == 'success':
            return True
        else:
            print("Error closing the session")

        return False

    def logout(self):
        """
            Close the session and notify the server to mark this client as inactive(i.e cannot take any request)
        """
        # First close the existing session and then logout
        if self.close_session():
            request = {
                "type": "logout",
                "username": self.username,
            }
            response = self.send_request(request)
            if response['status'] == 'success':
                return True
            else:
                print("Error closing the session")

            return False

    def forward_ticket_to_target(self, ticket_to_target, target_user, nonce):
        """Send the session ticket to the target client."""
        try:
           # request to peer contains username, nonce , its listening port and its ticket from server
            data = {
                "listening_port": self.listen_port,
                "user": self.username,
                "nonce": nonce
            }
            serialized_data = pickle.dumps(data)
            # encrypt the message with session key
            encrypted_message = encrypted_message_with_iv(self.session_key, serialized_data)

            # Create request body
            request_body = {
                "type": "forward_ticket",
                "ticket": ticket_to_target,
                "message": encrypted_message,
            }
            response, peer_socket = self.connect_to_peer(request_body)
            if response["status"] == "success":
                print(f"Ticket forwarded to {target_user} successfully.")

                # Fetch the verification from target
                nonce_rcv = response["verification_nonce"]
                decrypted_nonce = decrypt_message_with_iv(self.session_key, nonce_rcv).hex()
                # If peer is verified the session is established
                if decrement_nonce(nonce) == decrypted_nonce:
                    return peer_socket
                else:
                    print("Target verification failed.")
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

            if request["type"] == "forward_ticket":
                # Handle ticket forwarding
                print(f"Received ticket from {addr}")

                # Verify the ticket and accept connection
                verified, sender = self.process_ticket(request, peer_socket, addr)

                # If ticket is verified enter the chat
                if verified:
                    # Start threads for receiving and sending messages
                    print(
                        f"Session active with {sender} ({self.peer_host}:{self.peer_port}). (Enter your message or press 9 to exit)")
                    print("Please press 0 to continue") # to discard the data from main menu thread
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
            message = request["message"]

            # Decrypt and fetch data from the ticket
            decrypted_ticket = self.private_key.decrypt(
                ticket,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Deserialize the ticket to extract its contents
            ticket_data = pickle.loads(decrypted_ticket)
            self.session_key = ticket_data.get("session_key")
            initiator = ticket_data.get("initiator")
            nonce_in_ticket = ticket_data.get("nonce")

            # Use the session key to decrypt the message
            decrypted_data = decrypt_message_with_iv(self.session_key, message)
            decrypted_message = pickle.loads(decrypted_data)
            nonce_in_request = decrypted_message["nonce"]
            sender = decrypted_message["user"]

            # If the nonce or username dont match close the connection
            if (sender != initiator) and (nonce_in_ticket != nonce_in_request):
                peer_socket.send(pickle.dumps({"status": "error"}))
                return False, None


            # Update the addr as its peer host and update the listening port
            self.peer_host = addr[0]
            self.peer_port = decrypted_message["listening_port"]

            # Step 3:  decremented nonce by 1, encrypt it and send back to verify yourself
            verfication_nonce = decrement_nonce(nonce_in_ticket)
            encrypted_nonce = encrypted_message_with_iv(self.session_key, bytes.fromhex(verfication_nonce))

            print(f"Session established with {addr}.")
            peer_socket.send(pickle.dumps({"status": "success", "verification_nonce": encrypted_nonce}))
            return True, sender
        except Exception as e:
            print(f"Failed to process session ticket: {e}")
            return False, None

    def close_connection(self, peer_socket):
        """Close the current session and clean up resources."""
        if self.session_key:
            # Notifiy server
            if self.close_session():
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

        # signal send and receive message threads to stop
        self.stop_event.set() 


    def send_request(self, request):
        """
        Function to send request to server
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.server_host, self.server_port))
            client_socket.send(pickle.dumps(request))
            response = client_socket.recv(4096)
        return pickle.loads(response)

    def connect_to_peer(self, req):
        """
         Function to send message to peer
        """
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.connect((self.peer_host, self.peer_port))
        peer_socket.send(pickle.dumps(req))
        res = peer_socket.recv(4096)
        return pickle.loads(res), peer_socket

    def send_message(self, message, socket):
        """
        Encrypt and send message to peer
        """
        try:
            encrypted_message = encrypted_message_with_iv(self.session_key, message)
            socket.send(encrypted_message)
        except Exception as e:
            print(f"Failed to send the message: {e}")


    def send_messages(self, peer_socket):
        """Threaded method to handle sending messages in session."""
        # print("Enter your message or press 9 to exit the chat")
        while not self.stop_event.is_set():  # Check if stop_event is set:
            message = input()
            self.send_message(message.strip().encode('utf-8'), peer_socket)
            # Can print the input again but was repeated on console
            # formatted_text = format_chatbot_text_right(f"{self.username}:" + message)
            # print(f"{formatted_text}")

            if message == "9":
                print("Session terminated.")
                break
        self.close_connection(peer_socket)

    def receive_messages(self, peer_socket, sender):
        """Threaded method to handle new incoming messages in session."""
        while not self.stop_event.is_set():  # Check if stop_event is set:
            try:
                encrypted_message = peer_socket.recv(1024)
                message = decrypt_message_with_iv(self.session_key, encrypted_message).decode('utf-8')
                # Close the connection if peer closes it
                if message == '9':
                    print("Connection closed by the other client. Please enter 9 to exit")
                    break

                formatted_text = format_chatbot_text_left(f"{sender}: {message}")
                print(f"|{formatted_text}|")
            except Exception as e:
                if self.session_active:
                    print(f"Error listening to messages {e}")
                break
        # self.close_connection(peer_socket)

    def start_session(self):
        """
        Initiate a session with other client
        """
        target = input("Enter the username of the client to initiate a session with: ")

        # Request server for session key and open socket
        peer_socket = self.initiate_session(target)

        # If the connection is not established clean the resources
        if not self.session_key or not peer_socket:
            print("Session initiation failed. Try again or select another option.")
            self.close_session()
            return
        else:
            # Start threads for receiving and sending messages
            print(
                f"Session active with {target} ({self.peer_host}:{self.peer_port}). (Enter your message or press 9 to exit)")

            receive_thread = threading.Thread(target=self.receive_messages, args=(peer_socket, target))
            send_thread = threading.Thread(target=self.send_messages, args=(peer_socket,))
            receive_thread.start()
            send_thread.start()

            # Wait for both threads to finish before allowing the user to start another session
            receive_thread.join()
            send_thread.join()



def get_key_files(private_key_file="private_key.pem", generate=False):
    """
    Utility function to generate or read RSA key files
    """

    if not private_key_file:
        private_key_file = "private_key.pem"
    private_key = None

    # Load the key from the file
    if not generate:
        try:
            # Load private key from file
            with open(private_key_file, "rb") as private_key_file:
                private_key = serialization.load_pem_private_key(
                    private_key_file.read(),
                    password=None  # Provide a password if the key is encrypted
                )
        except Exception as e:
            print(f"Error fetching the key: {e}")
    else:
        # generate new keys
        private_key = generate_rsa_keypair()

    return private_key


def register_or_login():
    """
    Register or Login to server
    """
    print("Enter \n 1: Register \n 2:Login")
    choice = input()
    if choice == "1":
        username = input("Enter your username: ")
        filename = input(f"Enter your private key file name or press Enter to generate new RSA key pairs: ")
        generate_new = False if filename else True
        key = get_key_files(filename, generate_new)

        if not key:
            print("Exiting....")
            exit()

        client = Client(username, key)

        # Register the client to the server
        while not client.register():
            username = input("Enter your username: ")
            client.username = username
            client.register()
    elif choice == "2":
        # Existing user, can log in
        username = input("Enter your username: ")
        filename = input(f"Enter your private key file name or press Enter to use default: ")
        key = get_key_files(filename)

        if not key:
            print("Exiting....")
            exit()

        client = Client(username, key)

        if not client.login():
            print("Exiting....")
            exit()
    else:
        print("Invalid choice")
        exit()

    return client


if __name__ == "__main__":
    # Create a client object
    client = register_or_login()

    # Start a thread to listen for incoming messages
    listening_thread = threading.Thread(target=client.listen_for_messages, daemon=True)
    listening_thread.start()

    # Start the main thread
    while True:
        # If a session is on going pause the main thread
        while client.session_active:
            time.sleep(5)

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
            client.logout()
            print("Exiting...")
            break

        else:
            if choice != "0":
                print("Invalid choice. Please try again.")
            if client.session_active:
                client.old_message = choice  # This is the message to send to user not a menu choice
                while client.session_active:
                    # print("Session active. Going to sleep until the session is closed...")
                    time.sleep(5)

        time.sleep(3)
