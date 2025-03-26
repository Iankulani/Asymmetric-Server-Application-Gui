import socket
import os
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from threading import Thread

# Function to generate RSA keys and save them
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save the keys to files
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(private_pem)
        
    with open('public_key.pem', 'wb') as public_file:
        public_file.write(public_pem)
    
    return private_key, public_key

# Function to decrypt received messages
def decrypt_message(private_key, encrypted_message):
    original_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()

# Function to handle server-client communication in a separate thread
def handle_client(client_socket, private_key, gui):
    encrypted_message = client_socket.recv(1024)
    
    # Decrypt the message
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted message from client: {decrypted_message}")
    
    # Update the GUI with the decrypted message
    gui.update_received_message(decrypted_message)
    
    # Send a response back to the client
    response = "Message received and decrypted"
    client_socket.send(response.encode())
    
    # Close the connection
    client_socket.close()

# Setup server socket and start listening
def start_server(gui):
    server_ip = gui.server_ip_entry.get()
    server_port = int(gui.server_port_entry.get())

    # Create and bind the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)

    print(f"Server listening on {server_ip}:{server_port}...")

    # Load server's private key
    with open('private_key.pem', 'rb') as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None, backend=default_backend())

    # Accept incoming client connection
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Handle the client communication in a separate thread
    client_thread = Thread(target=handle_client, args=(client_socket, private_key, gui))
    client_thread.start()

    # Close the server socket after handling the client
    server_socket.close()

# GUI Class using Tkinter
class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Asymmetric Encryption Server")

        # Server IP and Port Entry
        self.server_ip_label = tk.Label(self.root, text="Server IP:")
        self.server_ip_label.pack()

        self.server_ip_entry = tk.Entry(self.root)
        self.server_ip_entry.insert(0, "127.0.0.1")  # Default IP
        self.server_ip_entry.pack()

        self.server_port_label = tk.Label(self.root, text="Server Port:")
        self.server_port_label.pack()

        self.server_port_entry = tk.Entry(self.root)
        self.server_port_entry.insert(0, "65432")  # Default Port
        self.server_port_entry.pack()

        # Start Server Button
        self.start_server_button = tk.Button(self.root, text="Start Server", command=self.start_server)
        self.start_server_button.pack()

        # Received Message Display Area
        self.received_message_label = tk.Label(self.root, text="Received Message:")
        self.received_message_label.pack()

        self.received_message_display = tk.Text(self.root, height=10, width=50)
        self.received_message_display.pack()

    def start_server(self):
        # Generate keys if not already present
        if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
            generate_keys()

        # Start the server in a separate thread
        thread = Thread(target=start_server, args=(self,))
        thread.start()

    def update_received_message(self, message):
        # Update the received message display area
        self.received_message_display.delete(1.0, tk.END)
        self.received_message_display.insert(tk.END, message)

# Main function to start the GUI application
def main():
    root = tk.Tk()
    gui = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
