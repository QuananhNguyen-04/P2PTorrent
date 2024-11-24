import socket
from threading import Thread
import os
from struct import pack
from torrent import generate_handshake

SERVER_HOST = "192.168.43.7"  # Listen on all available interfaces
SERVER_PORT = 681
BUFFER_SIZE = 16384  # 16KB
SEPARATOR = "<SEPARATOR>"


def handle_client(client_socket: socket.socket):
    print("handle_client")
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


def receive_file(client_socket: socket.socket, filename: str):
    with open(filename, "wb") as f:
        while True:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            f.write(bytes_read)
    print(f"Received file: {filename}")


def send_file(
    client_socket: socket.socket,
    filename: str,
    piece_index: int,
    begin_offset: int,
    piece_length: int,
):
    print(filename)
    if not os.path.exists(filename):
        client_socket.send("File not found".encode())
        return

    # Calculate the starting position within the file
    start_position = piece_index * piece_length + begin_offset
    end_position = (piece_index + 1) * piece_length
    try:
        with open(filename, "rb") as f:
            # Move to the start position of the requested piece
            f.seek(start_position)
            # Send the requested piece data only
            bytes_to_read = min(BUFFER_SIZE, end_position - start_position)
            bytes_read = f.read(bytes_to_read)
            print(start_position, end_position, len(bytes_read))
            new_offset = begin_offset + len(bytes_read)
            print(new_offset)
            message = (
                pack(
                    ">IBIII",
                    13 + len(bytes_read),
                    7,
                    piece_index,
                    new_offset,
                    len(bytes_read),
                )
                + bytes_read
            )
            # print(message)
            client_socket.sendall(message)

        print(
            f"Sent {piece_length} bytes from file: {filename}, starting at offset {start_position}"
        )

    except Exception as e:
        print(f"Error sending file piece: {e}")
        client_socket.send("Error sending file piece".encode())


def send_torrent(client_socket: socket.socket, filename_raw: str):
    try:
        with open(f"{filename_raw+ '.torrent'}", "rb") as f:
            torrent_data = f.read()

            message = (
                pack(">IBIII", 13 + len(torrent_data), 5, 0, 0, len(torrent_data))
                + torrent_data
            )
            client_socket.sendall(message)
            print(f"Sent torrent file: {filename_raw + '.torrent'}")
    except Exception as e:
        print(f"Error sending torrent file: {e}")
        client_socket.send("Error sending torrent file".encode())


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
