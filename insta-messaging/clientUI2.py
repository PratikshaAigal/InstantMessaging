import sys
from client2 import Clients
def start_client_ui():
    """
    Terminal-based user interface for the client.
    """
    print("Welcome to the Secure Messaging Client")
    username = input("Enter your username: ").strip()
    
    client = Clients(username)

    while True:
        print("\n--- Main Menu ---")
        print("1. Register")
        print("2. Initiate Session")
        print("3. Send Message")
        print("4. Exit")
        choice = input("Choose an option (1-4): ").strip()

        if choice == "1":
            try:
                client.register()
            except Exception as e:
                print(f"Error during registration: {e}")

        elif choice == "2":
            target = input("Enter the username of the target user: ").strip()
            try:
                client.initiate_session(target)
            except Exception as e:
                print(f"Error during session initiation: {e}")

        elif choice == "3":
            if client.peer_host and client.peer_port:
                message = input("Enter your message: ").strip()
                try:
                    client.send_message(message)
                except Exception as e:
                    print(f"Error while sending message: {e}")
            else:
                print("No active session. Please initiate a session first.")

        elif choice == "4":
            print("Exiting the client. Goodbye!")
            sys.exit(0)

        else:
            print("Invalid choice. Please try again.")

# Run the terminal UI if the script is executed
if __name__ == "__main__":
    start_client_ui()
