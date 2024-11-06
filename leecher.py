from urllib.parse import parse_qs, unquote, urlparse
import requests
import socket
# from socket import inet_ntoa
from socket import inet_ntoa#, AF_INET, SOCK_STREAM
from threading import Thread
from struct import pack, unpack
# from hashlib import sha1
from flask import Flask, request, jsonify
from torrent import Torrent, decode, generate_peer_id, urlencode, generate_handshake, write_torrent_file

app = Flask(__name__)
peers = []

def request_peers_from_tracker(tracker_url, info_hash, peer_id, port):
    # Build request parameters
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': 0,
        'compact': 1,
        'event': 'started'
    }
    
    # Send request to tracker
    url = f"http://{tracker_url}?{urlencode(params)}" # HTTP need to ping the tracker with urlencoded parameters
    print(f"Sending request to: {url}")
    
    response = requests.get(url)
    if not response.status_code == 200:
        print("Failed to connect to tracker, status code:", response.status_code)
        return
    
    data = response.content
    decoded_data = decode(data.decode())
    print(decoded_data)
    peers = decoded_data.get('peers')
    if isinstance(peers, bytes):
        peers = [peers[i:i+6] for i in range(0, len(peers), 6)]
        peer_list = [(inet_ntoa(peer[:4]), int.from_bytes(peer[4:], 'big')) for peer in peers]
    else:
        peer_list = [(peer['ip'], peer['port']) for peer in peers]
    
    print("Received peer list:")
    for(ip, port) in peer_list:
        print((ip,port))

    with open("peers_list.txt", "w") as file:
        for ip, port in peer_list:
            print(f"IP: {ip}, Port: {port}")
            file.write(f"{ip}:{port}\n")
    

# Announce peer departure to tracker
def announce_peer_leaving(tracker_url, info_hash, peer_id, port):
    # Build request parameters with 'stopped' event to signal departure
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': 0,
        'compact': 1,
        'event': 'stopped',
    }
    
    # Construct URL with encoded parameters
    url = f"http://{tracker_url}?{urlencode(params)}"
    print(f"Announcing peer departure to tracker: {url}")
    
    try:
        # Send the request to the tracker
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        if response.status_code == 200:
            print("Successfully informed tracker of peer departure.")
        else:
            print(f"Unexpected response from tracker: {response.status_code}")
    
    except requests.RequestException as e:
        print(f"Failed to announce peer departure: {e}")

def parse_magnet_link(magnet_link):
    """Extracts info_hash and tracker from a magnet link."""
    parsed_link = urlparse(magnet_link)
    if parsed_link.scheme != 'magnet':
        raise ValueError("Not a valid magnet link")
    # Parse the query parameters
    params = parse_qs(parsed_link.query)
    
    # Extract info_hash (in hex form) and tracker URL
    info_hash = params['xt'][0].split(':')[-1]  # Extract hash from 'urn:btih:<hash>'
    tracker_url = unquote(params['tr'][0])  # Decode URL

    # Optional: extract display name (dn) if available
    file_name = params.get('dn', [None])[0]

    return info_hash, tracker_url, file_name

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
                peers.append({'ip': ip, 'port': int(port)})
    except Exception as e:
        print(f"Failed to load peers, error: {str(e)}")

def upload_to_peer(ip, port, info_hash, peer_id, piece_data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        
        # Send handshake
        handshake = generate_handshake(info_hash.encode('utf-8'), peer_id.encode('utf-8'))
        s.send(handshake)
        
        # Receive handshake
        response = s.recv(len(handshake))
        if response != handshake:
            raise Exception("Handshake failed")
        
        # Send piece data (assuming we're uploading the first piece, piece index = 0)
        piece_index = 0
        piece_length = len(piece_data)
        piece_message = pack(">IIBIII", 9 + piece_length, 7, piece_index, 0, piece_length) + piece_data.encode('utf-8')
        s.send(piece_message)

        print(f"Uploaded piece {piece_index} to {ip}:{port}")
        s.close()
    except Exception as e:
        print(f"Failed to upload to {ip}:{port}, error: {str(e)}")

@app.route('/upload', methods=['POST'])
def upload_file():
    info_hash = request.json.get('info_hash')
    peer_id = request.json.get('peer_id')
    piece_data = request.json.get('piece_data')

    if not info_hash or not peer_id or not piece_data:
        return jsonify({'error': 'Invalid info hash, peer ID, or piece data!'}), 400

    threads = []
    for peer in peers:
        ip = peer['ip']
        port = int(peer['port'])
        t = Thread(target=upload_to_peer, args=(ip, port, info_hash, peer_id, piece_data))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    return jsonify({'message': 'Upload initiated to all peers!'}), 201

def download_from_peer(ip, port, info_hash, peer_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        
        # Send handshake
        handshake = generate_handshake(info_hash.encode('utf-8'), peer_id.encode('utf-8'))
        s.send(handshake)
        
        # Receive handshake
        response = s.recv(len(handshake))
        if response != handshake:
            raise Exception("Handshake failed")
        
        # Request a piece (assuming we're requesting the first piece, piece index = 0)
        piece_index = 0
        request_message = pack(">IIBIII", 13, 6, piece_index, 0, 16384)  # request message
        s.send(request_message)
        
        # Receive piece
        piece_data = s.recv(16384 + 13)  # piece data + message length and id
        with open(f"downloaded_piece_{piece_index}_{ip}_{port}", "wb") as f:
            f.write(piece_data[13:])  # Exclude message length and id

        print(f"Downloaded piece {piece_index} from {ip}:{port}")
        s.close()
    except Exception as e:
        print(f"Failed to download from {ip}:{port}, error: {str(e)}")

@app.route('/download', methods=['POST'])
def download_file():
    info_hash = request.json.get('info_hash')
    peer_id = request.json.get('peer_id')

    if not info_hash or not peer_id:
        return jsonify({'error': 'Invalid info hash or peer ID!'}), 400

    threads = []
    for peer in peers:
        ip = peer['ip']
        port = int(peer['port'])
        t = Thread(target=download_from_peer, args=(ip, port, info_hash, peer_id))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    return jsonify({'message': 'Download initiated from all peers!'}), 201
def __initTorrent__(tracker_address, filename = 'peer.txt', torrentFile = './peer.torrent'):
    # tracker_url='http://10.0.184.207:9999'
    print("__initTorrent__")
    # tracker_url = 'http://127.0.0.1:9999'
    comment='init Torrent'
    write_torrent_file(torrentFile, filename, tracker_address,\
        comment)
    
def get_router_ip():
    try:
        # Connect to an external site and get the socket's local address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print("Could not determine local IP:", e)
        return None
    

class Peer:
    def __init__(self, port, tracker_address): # tracker is only for testing
        self.ip = get_router_ip()
        self.peer_id = generate_peer_id()
        self.port = port
        self.tracker_address = tracker_address
        self.torrents = {}
    def add_torrent_to_tracker(self, filename):
        filename_without_extension = filename.split('.')[0]
        torrentFile = f'./{filename_without_extension + str(len(self.torrents))}.torrent'
        __initTorrent__(self.tracker_address, filename, torrentFile=torrentFile)
        torrent = Torrent(torrentFile, self.peer_id)
        tracker_url = torrent.data["announce"]
        info_hash = torrent.info_hash
        peer_id = torrent.peer_id
        request_peers_from_tracker(tracker_url, info_hash, peer_id, self.port)
        
        self.torrents[info_hash] = {'filename': filename, 
                                    'torrentFile': torrentFile, 
                                    'peer_id': peer_id}
    
    def parse_magnet_link(magnet_link):
        """Extracts info_hash and tracker from a magnet link."""
        parsed_link = urlparse(magnet_link)
        if parsed_link.scheme != 'magnet':
            raise ValueError("Not a valid magnet link")
        
        # Parse the query parameters
        params = parse_qs(parsed_link.query)
        
        # Extract info_hash (in hex form) and tracker URL
        info_hash = params['xt'][0].split(':')[-1]  # Extract hash from 'urn:btih:<hash>'
        tracker_url = unquote(params['tr'][0])  # Decode URL

        # Optional: extract display name (dn) if available
        file_name = params.get('dn', [None])[0]

        return info_hash, tracker_url, file_name

    def connect_to_tracker_via_magnet(self, magnet_file):
        """Parses the magnet link and requests peers from the tracker."""
        magnet_link = open(magnet_file, 'r').read()
        print(magnet_link)
        info_hash, tracker_url, file_name = parse_magnet_link(magnet_link)
        
        # Connect to the tracker
        print(f"Connecting to tracker for {file_name if file_name else 'unknown file'}...")
        request_peers_from_tracker(tracker_url, info_hash, self.peer_id, self.port)

        self.torrents[info_hash] = {'filename': file_name, 
                                    'torrentFile': magnet_file, 
                                    'peer_id': self.peer_id}

    def download_from_peer(self, info_hash, peer_id, filename):
        download_file(info_hash, peer_id, filename)
    # def __del__(self):
        # announce_peer_leaving(self.tracker_address, info_hash, peer_id, self.port)
    def close(self):
        for info_hash in self.torrents:
            announce_peer_leaving(self.tracker_address, 
                                info_hash, 
                                self.torrents[info_hash]['peer_id'], 
                                self.port)
if __name__ == '__main__':
    
    # host = get_router_ip()
    port: str = input("Type your port... ")  # Get decide port (for testing)
    if port.isdigit(): # verify the testing
        port = int(port)
        if  not 0 < port < 65536:
            TypeError("The port must be between 1 and 65535")
        # __initTorrent__(f"{host}:{9999}")

    #     torrent_file = './peer.torrent'  # Relative path is easier
    #     torrent = Torrent(torrent_file)
    #     tracker_url = torrent.data["announce"]  # Lấy URL tracker từ tệp torrent
    #     info_hash = torrent.info_hash  # Lấy info_hash từ tệp torrent
    #     peer_id = torrent.peer_id  # Lấy peer_id được tạo
        
        # request_peers_from_tracker(tracker_url, info_hash, peer_id, port)
        # load_peers()
        # print(peers)
        # app.run(port=5000)
        # upload_file()

        # announce_peer_leaving(tracker_url, info_hash, peer_id, port)
        peer = Peer(port, f"{get_router_ip()}:9999")
        peer.connect_to_tracker_via_magnet("./file20.magnet")
        app.run(port=5000)
        peer.close()