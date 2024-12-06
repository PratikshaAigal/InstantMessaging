# Step 1: Run the Server
Start the server to listen for client connections and manage session keys.


`python server.py`
# Step 2: Register Clients
Start each client, register them with the server, and initiate communication.

Client A:

`python client.py`
After starting the client:

Enter the username for Client A when prompted.
The client will automatically register with the server.
Client B:
`
python client.py
`


After starting the client:

Enter the username for Client B when prompted.
The client will automatically register with the server.
Step 3: Initiate a Session
To initiate a secure session between the two clients:

On Client A's console, run:


`client.initiate_session("Client_B_Username")`

Replace "Client_B_Username" with the actual username of Client B.

Client B will receive the session key automatically.

Step 4: Exchange Messages
After the session is established, the clients can send and receive encrypted messages.

On Client A's console, send a message:


`client.send_message("Hello, Client B!")`

On Client B's console, the decrypted message will appear:


`Message from <Client A>: Hello, Client B!`

Similarly, Client B can send messages using:


`client.send_message("Hello, Client A!")`

Step 5: Terminate the Session
When the conversation ends, terminate the session:

On Client A or B, run:

`client.terminate_session()`

This will notify the server, discard the session key, and mark both clients as idle.

