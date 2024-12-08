import socket
import threading
import pickle

clients = {}  # Stores active clients as {username: (socket, state)}
sessions = {}  # Active sessions {initiator: target}


def handle_client(client_socket, username):
    while True:
        try:
            data = pickle.loads(client_socket.recv(4096))
            if not data:
                break

            # Handle different types of client requests
            if data["type"] == "list_clients":
                available_clients = [
                    f"{client} ({state})"
                    for client, (_, state) in clients.items()
                    if client != username
                ]
                client_socket.send(
                    pickle.dumps({"type": "client_list", "clients": available_clients})
                )

            elif data["type"] == "initiate_session":
                target = data["target"]
                if target in clients and clients[target][1] == "Idle":
                    # Mark both clients as busy
                    clients[username] = (client_socket, "Busy")
                    clients[target] = (clients[target][0], "Busy")
                    sessions[username] = target
                    sessions[target] = username

                    # Notify both clients
                    clients[target][0].send(
                        pickle.dumps(
                            {"type": "session_notification", "initiator": username}
                        )
                    )
                    client_socket.send(
                        pickle.dumps({"type": "session_confirmed", "target": target})
                    )
                    print(f"Session established between {username} and {target}.")
                else:
                    client_socket.send(
                        pickle.dumps(
                            {"type": "error", "message": "Target is not available."}
                        )
                    )

            elif data["type"] == "send_message":
                target = sessions.get(username)
                if target and target in clients:
                    clients[target][0].send(
                        pickle.dumps(
                            {
                                "type": "new_message",
                                "sender": username,
                                "message": data["message"],
                            }
                        )
                    )
                    print(f"{username} to {target}: {data['message']}")
                else:
                    client_socket.send(
                        pickle.dumps(
                            {"type": "error", "message": "No active session."}
                        )
                    )

            elif data["type"] == "end_session":
                target = sessions.pop(username, None)
                if target:
                    sessions.pop(target, None)
                    # Mark both clients as idle
                    clients[username] = (client_socket, "Idle")
                    clients[target] = (clients[target][0], "Idle")
                    clients[target][0].send(
                        pickle.dumps(
                            {"type": "session_ended", "message": f"{username} ended the session."}
                        )
                    )
                    client_socket.send(
                        pickle.dumps(
                            {"type": "session_ended", "message": f"Session with {target} ended."}
                        )
                    )
                    print(f"Session ended between {username} and {target}.")
                else:
                    client_socket.send(
                        pickle.dumps(
                            {"type": "error", "message": "No active session to end."}
                        )
                    )

        except Exception as e:
            print(f"Error handling client {username}: {e}")
            break

    # Cleanup on client disconnect
    clients.pop(username, None)
    target = sessions.pop(username, None)
    if target:
        sessions.pop(target, None)
        clients[target] = (clients[target][0], "Idle")
        clients[target][0].send(
            pickle.dumps(
                {"type": "session_ended", "message": f"{username} disconnected."}
            )
        )
    client_socket.close()
    print(f"Client {username} disconnected.")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 12345))
    server.listen(5)
    print("Server running on 127.0.0.1:12345")

    while True:
        client_socket, addr = server.accept()
        try:
            credentials = pickle.loads(client_socket.recv(4096))
            username = credentials["username"]

            if username in clients:
                client_socket.send(
                    pickle.dumps(
                        {"type": "error", "message": "Username already taken."}
                    )
                )
                client_socket.close()
            else:
                clients[username] = (client_socket, "Idle")
                client_socket.send(
                    pickle.dumps({"type": "welcome", "message": f"Welcome, {username}!"})
                )
                print(f"Client {username} registered.")
                threading.Thread(target=handle_client, args=(client_socket, username)).start()
        except Exception as e:
            print(f"Error during client registration: {e}")


if __name__ == "__main__":
    main()
