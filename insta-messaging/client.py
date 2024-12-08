import socket
import threading
import pickle


class Client:
    def __init__(self, username, server_host="127.0.0.1", server_port=12345):
        self.username = username
        self.server_host = server_host
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer = None
        self.conversation_log = []  # To maintain a conversation history

    def start(self):
        self.socket.connect((self.server_host, self.server_port))
        self.socket.send(pickle.dumps({"username": self.username}))
        response = pickle.loads(self.socket.recv(4096))
        if response["type"] == "welcome":
            print(response["message"])
            self.show_options()
            threading.Thread(target=self.listen_for_responses, daemon=True).start()
            self.menu()

    def listen_for_responses(self):
        while True:
            try:
                data = pickle.loads(self.socket.recv(4096))
                if data["type"] == "client_list":
                    print("\nAvailable clients:")
                    for client in data["clients"]:
                        print(client)
                    self.show_options()
                elif data["type"] == "session_notification":
                    print(f"\nSession initiated by {data['initiator']}.")
                    self.peer = data["initiator"]
                    self.show_options()
                elif data["type"] == "session_confirmed":
                    print(f"Session established with {data['target']}.")
                    self.peer = data["target"]
                    self.show_options()
                elif data["type"] == "new_message":
                    self.conversation_log.append(f"{data['sender']}: {data['message']}")  # Log the message
                    self.display_conversation()
                    self.show_options()
                elif data["type"] == "session_ended":
                    print(f"\n{data['message']}")
                    self.peer = None
                    self.conversation_log = []  # Clear conversation history on session end
                    self.show_options()
                elif data["type"] == "error":
                    print(f"\nError: {data['message']}")
                    self.show_options()
            except Exception as e:
                print(f"Error receiving data: {e}")
                break

    def display_conversation(self):
        """
        Display the full conversation log so far.
        """
        print("\nConversation:")
        for message in self.conversation_log:
            print(message)
        print("\n")

    def show_options(self):
        print("\nOptions:")
        print("1. List available clients")
        print("2. Initiate session")
        print("3. Send message")
        print("4. End session")
        print("5. Exit")

    def menu(self):
        while True:
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                self.socket.send(pickle.dumps({"type": "list_clients"}))
            elif choice == "2":
                if self.peer:
                    print("You are already in a session. End it before starting a new one.")
                    continue
                target = input("Enter the username of the client to connect: ").strip()
                self.socket.send(pickle.dumps({"type": "initiate_session", "target": target}))
            elif choice == "3":
                if not self.peer:
                    print("No active session. Initiate a session first.")
                    continue
                message = input("You: ").strip()
                self.conversation_log.append(f"You: {message}")  # Log your own message
                self.socket.send(pickle.dumps({"type": "send_message", "message": message}))
                self.display_conversation()  # Show updated conversation
            elif choice == "4":
                if not self.peer:
                    print("No active session to end.")
                    continue
                self.socket.send(pickle.dumps({"type": "end_session"}))
                self.peer = None
                self.conversation_log = []  # Clear the conversation history
            elif choice == "5":
                self.socket.close()
                print("Exited successfully.")
                break
            else:
                print("Invalid choice. Try again.")


if __name__ == "__main__":
    username = input("Enter your username: ").strip()
    client = Client(username)
    client.start()
