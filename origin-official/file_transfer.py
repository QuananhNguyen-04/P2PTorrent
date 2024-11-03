import socket
from threading import Thread
import os
from torrent import *
SERVER_HOST = '0.0.0.0'  # Listen on all available interfaces
SERVER_PORT = 6881
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

def handle_client(client_socket):
    received = client_socket.recv(BUFFER_SIZE).decode()
    print(received)
    if SEPARATOR in received:
        command, filename, info_hash, peer_id = received.split(SEPARATOR)
        
        handshake = generate_handshake(info_hash, peer_id)
        client_socket.send(handshake.encode())

        response = client_socket.recv(len(handshake)).decode()
        if response != handshake:
            print("Handshake failed")
            client_socket.close()
            return
        
        if command == "UPLOAD":
            receive_file(client_socket, filename)
        elif command == "DOWNLOAD":
            send_file(client_socket, filename)
    else:
        print("Invalid command received")
    
    client_socket.close()

def receive_file(client_socket, filename):
    with open(filename, "wb") as f:
        while True:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:    
                break
            f.write(bytes_read)
    print(f"Received file: {filename}")

def send_file(client_socket, filename):
    if not os.path.exists(filename):
        client_socket.send("File not found".encode())
        return

    with open(filename, "rb") as f:
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            client_socket.sendall(bytes_read)
    print(f"Sent file: {filename}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Listening on {SERVER_HOST}:{SERVER_PORT}...")
    
    while True:
        client_socket, address = server_socket.accept()
        print(f"Accepted connection from {address}")
        client_handler = Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()