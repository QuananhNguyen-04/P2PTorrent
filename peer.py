from math import ceil
import os
from urllib.parse import parse_qs, unquote, urlparse
import requests
import socket

# from socket import inet_ntoa
from socket import inet_ntoa  # , AF_INET, SOCK_STREAM
from threading import Lock, Thread
from struct import pack, unpack
from file_transfer import send_file, receive_file, send_torrent

# from hashlib import sha1
from flask import Flask, redirect, request, jsonify, render_template, url_for
from torrent import (
    Torrent,
    decode,
    generate_peer_id,
    urlencode,
    generate_handshake,
    write_torrent_file,
)

app = Flask(__name__)
peers = []
peer_instance = None


def get_router_ip():
    return socket.gethostbyname(socket.gethostname())


def initialize_peer_instance():
    global peer_instance
    if peer_instance is None:
        # Replace these with your actual peer configuration
        port = 6881
        tracker_address = f"{get_router_ip()}:9999"
        peer_instance = Peer(port, tracker_address)
    return peer_instance


def request_peers_from_tracker(tracker_url, info_hash, peer_id, port):
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": 0,
        "compact": 1,
        "event": "started",
    }

    # Send request to tracker
    url = f"http://{tracker_url}?{urlencode(params)}"  # HTTP need to ping the tracker with urlencoded parameters
    print(f"Sending request to: {url}")

    response = requests.get(url)
    if not response.status_code == 200:
        print("Failed to connect to tracker, status code:", response.status_code)
        return

    data = response.content
    decoded_data = decode(data.decode())
    print(decoded_data)
    peers = decoded_data.get("peers")
    if isinstance(peers, bytes):
        peers = [peers[i : i + 6] for i in range(0, len(peers), 6)]
        peer_list = [
            (inet_ntoa(peer[:4]), int.from_bytes(peer[4:], "big")) for peer in peers
        ]
    else:
        peer_list = [(peer["ip"], peer["port"]) for peer in peers]

    print("Received peer list:")
    for ip, port in peer_list:
        print((ip, port))

        with open("peers_list.txt", "w") as file:
            for ip, port in peer_list:
                file.write(f"{ip}:{port}\n")
        return peers


# Announce peer's departure to tracker
def announce_peer_leaving(tracker_url, info_hash, peer_id, port):
    # Build request parameters with 'stopped' event to signal departure
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": 0,
        "compact": 1,
        "event": "stopped",
    }
    url = f"http://{tracker_url}?{urlencode(params)}"
    try:
        # Send the request to the tracker
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        if response.status_code == 200:
            print("Tracker informed of peer departure")
    except requests.RequestException as e:
        print(f"Failed to announce departure: {e}")


# Parse a magnet link for info_hash and tracker URL
def parse_magnet_link(magnet_link):
    parsed = urlparse(magnet_link)
    if parsed.scheme != "magnet":
        raise ValueError("Invalid magnet link")
    params = parse_qs(parsed.query)
    info_hash = params["xt"][0].split(":")[-1]
    tracker_url = unquote(params["tr"][0])
    file_name = params.get("dn", [None])[0]

    return info_hash, tracker_url, file_name


# Peer server that accepts connections from other peers
class PeerServer:
    def __init__(self, host="0.0.0.0", peer=None):
        self.host = host
        self.port = peer.port
        self.peer_id = peer.peer_id
        self.server_socket = None
        self.running = False
        self.peer: Peer = peer
        self.accept_thread = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        print(f"Peer server running on {self.host}:{self.port}")
        self.accept_thread = Thread(target=self.accept_connections)
        self.accept_thread.start()

    def accept_connections(self):
        """Accept incoming connections."""
        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                print(f"Accepted connection from {addr}")
                # Handle each client in a separate thread
                Thread(target=self.handle_client, args=(client_socket,)).start()
        except OSError:
            print("Server stopped accepting connections.")

    def handle_client(self, client_socket):
        try:
            handshake, info_hash = self.receive_handshake(client_socket)
            client_socket.sendall(handshake)

            self.receive_request(client_socket, info_hash)
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            client_socket.close()

    def receive_request(self, client_socket, info_hash: str):
        while True:
            request = client_socket.recv(4)  # message length + message id

            (length,) = unpack(">I", request)
            # print(f"Received request with length {length}")
            message = client_socket.recv(length)
            message_id = message[0]  # The first byte after length is the message ID
            print(message_id)
            filename = self.peer.torrents[info_hash]["filename"]
            filename_without_extension = filename.split(".")[0]
            if message_id == 6:
                print("=======\nHandling request")
                # Handle a request message (message ID 6)
                _, piece_index, begin, piece_length = unpack(">BIII", message)
                print(
                    f"Request received for piece {piece_index} from offset {begin} with length {piece_length}"
                )

                # Here you would respond with the requested piece data.
                if info_hash in self.peer.torrents:
                    send_file(client_socket, filename, piece_index, begin, piece_length)
                else:
                    raise Exception("File not found")
                # You can retrieve the piece data from storage and send it back.
            elif message_id == 4:
                print("=======\nsending torrent")
                # Handle a have message (message ID 4)
                send_torrent(client_socket, filename_without_extension)
            elif message_id == 7:
                # Handle a piece message (message ID 7)
                _, piece_index, begin = unpack(">BII", message[:9])
                piece_data = message[9:]
                print(
                    f"Received piece {piece_index} starting at {begin} with data length {len(piece_data)}"
                )

            # Add handling for other message types as necessary
            else:
                print(f"Received unknown message ID {message_id}")

    def receive_handshake(self, client_socket):
        """Receive and validate a BitTorrent-style handshake from a peer."""
        try:
            # The expected handshake message length is 68 bytes
            handshake = client_socket.recv(68)
            if len(handshake) < 68:
                raise ValueError("Incomplete handshake received.")

            print("Received handshake:", handshake)
            # print(len(handshake))
            # Parse the handshake message

            pstr = handshake[1:20]  # Protocol string (19 bytes)
            info_hash = handshake[28:48]  # Info hash (20 bytes)
            handshake = generate_handshake(info_hash=info_hash, peer_id=self.peer_id)
            # Verify the protocol string

            if pstr != b"BitTorrent protocol":
                raise ValueError("Invalid protocol string in handshake.")

            # print("Received handshake message.")
            # print(f"Protocol String: {pstr.decode()}")
            # print(f"Info Hash: {info_hash}, {info_hash.hex()}")
            # print(f"Peer ID: {peer_id.decode(errors='replace')}")

            return handshake, info_hash.hex()

        except Exception as e:
            print(f"Error receiving handshake: {e}")
            return None, None

    def stop(self):
        """Stop the socket server."""
        self.running = False
        # Trigger server shutdown by closing the listening socket
        if self.server_socket:
            self.server_socket.close()
        if self.accept_thread:
            self.accept_thread.join()
        print("Peer server has been stopped.")


def connect_to_tracker_via_magnet(magnet_link, peer_id, port):
    """Parses the magnet link and requests peers from the tracker."""
    info_hash, tracker_url, file_name = parse_magnet_link(magnet_link)

    # Connect to the tracker
    print(f"Connecting to tracker for {file_name if file_name else 'unknown file'}...")
    request_peers_from_tracker(tracker_url, info_hash, peer_id, port)


def load_peers():
    try:
        with open("peers_list.txt", "r") as file:
            for line in file:
                ip, port = line.strip().split(":")
                peers.append({"ip": ip, "port": int(port)})
    except Exception as e:
        print(f"Failed to load peers, error: {str(e)}")


@app.route("/")
def index():
    peer = initialize_peer_instance()
    torrents = peer.torrents
    return render_template("./index.html", torrents=torrents, peer_id=peer.peer_id)


def upload_to_peer(ip, port, info_hash, peer_id, piece_data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))

        # Send handshake
        handshake = generate_handshake(
            info_hash.encode("utf-8"), peer_id.encode("utf-8")
        )
        s.send(handshake)

        # Receive handshake
        response = s.recv(len(handshake))
        if response != handshake:
            raise Exception("Handshake failed")

        # Send piece data (assuming we're uploading the first piece, piece index = 0)
        piece_index = 0
        piece_length = len(piece_data)
        piece_message = pack(
            ">IIBIII", 9 + piece_length, 7, piece_index, 0, piece_length
        ) + piece_data.encode("utf-8")
        s.send(piece_message)

        print(f"Uploaded piece {piece_index} to {ip}:{port}")
        s.close()
    except Exception as e:
        print(f"Failed to upload to {ip}:{port}, error: {str(e)}")


@app.route("/upload", methods=["POST"])
def upload_file():
    try:

        file = request.files["file"]
        file_path = os.path.join(os.getcwd(), file.filename)

        file.save(file_path)
        filename = file.filename
        print(f"File {filename} saved to {file_path}")

        peer = initialize_peer_instance()

        peer.add_torrent_to_tracker(filename)
        print(f"Torrent for {filename} added to tracker")

        return redirect(url_for("index"))
    except Exception as e:
        return {"error": str(e)}, 400


def download_from_peer(
    ip, port, info_hash, peer_id, filename, meta_info, meta_lock, pieces
):
    filename_without_extension = filename.split(".")[0]

    def exchange_metadata(s, filename_without_extension) -> dict:
        request_torrent = pack(">IBIII", 13, 4, 0, 0, 0)
        s.sendall(request_torrent)
        torrent_file = s.recv(17)
        _, message_id, _, _, piece_length = unpack(">IBIII", torrent_file)
        if message_id != 5:
            raise Exception("Expected torrent file (message ID 5)")
        torrent_data = s.recv(piece_length)
        print(torrent_data)
        metadata = decode(torrent_data.decode())

        with open(f"{filename_without_extension}_new.torrent", "wb") as f:
            f.write(torrent_data)
        return metadata["info"]

    def exchange_handshake(s, info_hash, peer_id):
        handshake = generate_handshake(info_hash, peer_id)
        print(handshake)
        s.sendall(handshake)
        response = s.recv(len(handshake))
        if len(response) != len(handshake):
            raise Exception("Handshake failed")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        exchange_handshake(s, info_hash, peer_id)

        if not meta_info:
            try:
                metadata_info = exchange_metadata(s, filename_without_extension)
                with meta_lock:
                    meta_info.update(metadata_info)
            except Exception as e:
                print(f"Failed to exchange metadata, error: {str(e)}")
        print("meta_info:", meta_info)

        if meta_info:
            file_length = metadata_info["length"]
            piece_length = metadata_info["piece length"]
            print(meta_info)
            piece_num = ceil(file_length / piece_length)
            with meta_lock:
                if pieces is None:
                    pieces = list(range(piece_num))
        print("pieces:", pieces)
        # Request a piece (assuming we're requesting the first piece, piece index = 0)
        while len(pieces) > 0:
            piece_index = pieces.pop(0)
            piece_offset = 0
            max_offset = (
                min(file_length, (piece_index + 1) * piece_length)
                - piece_index * piece_length
            )
            hash_data_block = {}
            while piece_offset < max_offset:
                request_message = pack(
                    ">IBIII", 13, 6, piece_index, piece_offset, piece_length
                )  # request message

                s.sendall(request_message)
                header = s.recv(17)
                (
                    message_length,
                    message_id,
                    received_piece_index,
                    received_begin_offset,
                    data_length,
                ) = unpack(">IBIII", header)

                if message_id != 7:
                    raise Exception("Expected piece message (message ID 7)")
                piece_data = s.recv(data_length)
                hash_data_block[piece_offset] = piece_data
                piece_offset = received_begin_offset
                print("piece_offset", piece_offset)
            with open(f"{filename.split('.')[0]}_{piece_index}.{filename.split('.')[1]}", "wb") as f:
                for offset, piece_data in sorted(hash_data_block.items()):
                    f.write(piece_data)

            print(
                f"Downloaded piece {piece_index} from {ip}:{port} to {filename}_{piece_index}"
            )

    except s.timeout:
        print("Connection timed out - no response from peer.")
    except ConnectionRefusedError:
        print("Connection refused by the peer.")
    except Exception as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Failed to download from {ip}:{port}, error: {str(e)}")
    finally:
        s.close()


@app.route("/download/<info_hash>?filename=<filename>", methods=["POST"])
def download_file(info_hash, filename):

    # info_hash = request.form.get("info_hash")
    if not info_hash:
        return jsonify({"error": "Invalid info hash!"}), 400
    peer = initialize_peer_instance()
    peer_id = peer.peer_id
    tracker_url = peer.tracker_address
    peers = request_peers_from_tracker(tracker_url, info_hash, peer.peer_id, peer.port)
    peers = [peer for peer in peers if peer["peer id"] != peer_id]
    threads = []
    metadata_info = {}
    metadata_lock = Lock()
    data_pieces = None
    for peer in peers:
        ip = peer["ip"]
        port = int()

    for peer in peers:
        if peer["peer id"] == peer_id:
            continue
        ip = peer["ip"]
        port = int(peer["port"])
        print(f"Downloading {filename} from {ip}:{port}")
        t = Thread(
            target=download_from_peer,
            args=(
                ip,
                port,
                info_hash,
                peer_id,
                filename,
                metadata_info,
                metadata_lock,
                data_pieces,
            ),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    if metadata_info is None:
        return jsonify({"error": "Failed to exchange metadata"}), 500
    piece_num = ceil(metadata_info["length"] / metadata_info["piece length"])
    # merge files
    with open(filename.split(".")[0] + "new." + filename.split(".")[1], "wb") as f:
        for i in range(piece_num):
            print(f"merging {filename}_{i}")
            with open(f"{filename.split('.')[0]}_{i}.{filename.split('.')[1]}", "rb") as piece_file:
                f.write(piece_file.read())
            os.remove(f"{filename.split('.')[0]}_{i}.{filename.split('.')[1]}")

    return jsonify({"message": "Download initiated from all peers!"}), 201


@app.route("/joinnew", methods=["POST"])
def join():
    try:
        peer = initialize_peer_instance()
        peer_id = peer.peer_id
        port = peer.port

        magnet_text = request.form.get("magnet")
        magnet_file = request.files.get("magnet_file")
        if magnet_text:
            print(magnet_text)

        elif magnet_file:
            print(magnet_file)
            magnet_text = magnet_file.read().decode("utf-8").strip()
            print(f"Magnet link extracted from file: {magnet_text}")
        else:
            return {"error": "Invalid magnet link or file"}, 400

        info_hash, tracker_url, filename = parse_magnet_link(magnet_text)
        request_peers_from_tracker(tracker_url, info_hash, peer_id, port)
        print(
            f"Connecting to tracker for {filename if filename else 'unknown file'}..."
        )

        peer.torrents[info_hash] = {
            "filename": filename,
            "torrentFile": filename,
            "peer_id": peer_id,
        }

        return redirect(url_for("index"))
    except Exception as e:
        return {"error": str(e)}, 400


def __initTorrent__(tracker_address, filename="peer.txt", torrentFile="./peer.torrent"):
    # tracker_url='http://10.0.184.207:9999'
    print("__initTorrent__")
    # tracker_url = 'http://127.0.0.1:9999'
    comment = "init Torrent"
    write_torrent_file(torrentFile, filename, tracker_address, comment)


class Peer:
    def __init__(self, port, tracker_address):  # tracker is only for testing
        self.ip = get_router_ip()
        self.peer_id = generate_peer_id()
        self.port = port
        self.tracker_address = tracker_address
        self.torrents = {}
        self.server = PeerServer(peer=self)

    def add_torrent_to_tracker(self, filename):
        filename_without_extension = filename.split(".")[0]
        torrentFile = f"./{filename_without_extension}.torrent"
        __initTorrent__(self.tracker_address, filename, torrentFile=torrentFile)
        torrent = Torrent(torrentFile, self.peer_id)
        tracker_url = torrent.data["announce"]
        info_hash = torrent.info_hash

        request_peers_from_tracker(tracker_url, info_hash, self.peer_id, self.port)

        self.torrents[info_hash] = {
            "filename": filename,
            "torrentFile": torrentFile,
            "peer_id": self.peer_id,
        }
        # print(self.torrents)

    def parse_magnet_link(magnet_link):
        """Extracts info_hash and tracker from a magnet link."""
        parsed_link = urlparse(magnet_link)
        if parsed_link.scheme != "magnet":
            raise ValueError("Not a valid magnet link")

        # Parse the query parameters
        params = parse_qs(parsed_link.query)

        # Extract info_hash (in hex form) and tracker URL
        info_hash = params["xt"][0].split(":")[
            -1
        ]  # Extract hash from 'urn:btih:<hash>'
        tracker_url = unquote(params["tr"][0])  # Decode URL

        # Optional: extract display name (dn) if available
        file_name = params.get("dn", [None])[0]

        return info_hash, tracker_url, file_name

    def connect_to_tracker_via_magnet(self, magnet_file):
        """Parses the magnet link and requests peers from the tracker."""
        magnet_link = open(magnet_file, "r").read()

        info_hash, tracker_url, file_name = parse_magnet_link(magnet_link)

        # Connect to the tracker
        print(
            f"Connecting to tracker for {file_name if file_name else 'unknown file'}..."
        )
        request_peers_from_tracker(tracker_url, info_hash, self.peer_id, self.port)

        self.torrents[info_hash] = {
            "filename": file_name,
            "torrentFile": magnet_file,
            "peer_id": self.peer_id,
        }

    def start_server(self):
        self.server.start()

    def stop_server(self):
        self.server.stop()

    def close(self):
        for info_hash in self.torrents:
            announce_peer_leaving(
                self.tracker_address,
                info_hash,
                self.torrents[info_hash]["peer_id"],
                self.port,
            )


if __name__ == "__main__":

    # host = get_router_ip()
    # port: str = input("Type your port... ")  # Get decide port (for testing)
    port = "4900"
    if port.isdigit():  # verify the testing
        port = int(port)
        if not 1024 < port < 65536:
            TypeError("The port must be between 1025 and 65535")

        peer_instance = Peer(port, f"{get_router_ip()}:9999")
        peer_instance.add_torrent_to_tracker("Interface.zip")
        server_thread = Thread(target=peer_instance.start_server, daemon=True)
        server_thread.start()
        app.run(port=peer_instance.port)
        peer_instance.stop_server()
        server_thread.join()
        peer_instance.close()
