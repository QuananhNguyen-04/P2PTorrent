import requests
import socket
from socket import inet_ntoa
from socket import inet_ntoa, socket, AF_INET, SOCK_STREAM
from threading import Thread
from struct import pack, unpack
from hashlib import sha1
from flask import Flask, request, jsonify
from time import sleep, time
from torrent import *

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
    url = f"{tracker_url}?{urlencode(params)}"
    print(f"Sending request to: {url}")
    
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.content
        decoded_data = decode(data.decode())
        
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
    else:
        print("Failed to connect to tracker, status code:", response.status_code)

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
def __initTorrent__():
    tracker_url='http://10.0.184.207:9999'
    torrentFile='/CNetworks/official/peer.torrent'
    comment='init Torrent'
    write_torrent_file(torrentFile,'peer.txt',tracker_url,\
        comment)
if __name__ == '__main__':
    # __initTorrent__()
    torrent_file = '/CNetworks/official/peer.torrent'  # Thay thế bằng đường dẫn tới tệp torrent của bạn
    torrent = Torrent(torrent_file)
    tracker_url = torrent.data["announce"]  # Lấy URL tracker từ tệp torrent
    info_hash = torrent.info_hash  # Lấy info_hash từ tệp torrent
    peer_id = torrent.peer_id  # Lấy peer_id được tạo
    port = 6881  # Example port number
    request_peers_from_tracker(tracker_url, info_hash, peer_id, port)
    load_peers()
    print(peers)
    app.run(port=5000)
