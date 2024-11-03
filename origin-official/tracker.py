from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from logging import basicConfig, info, INFO
from socket import inet_aton
from struct import pack
from urllib.parse import parse_qs
from urllib.request import urlopen
from bencode import encode

def decode_request(path):
    if path[:1] == "?":
        path = path[1:]
    elif path[:2] == "/?":
        path = path[2:]
    return parse_qs(path)

def add_peer(torrents, info_hash, peer_id, ip, port):
    if info_hash in torrents:
        if (peer_id, ip, port) not in torrents[info_hash]:
            torrents[info_hash].append((peer_id, ip, port))
    else:
        torrents[info_hash] = [(peer_id, ip, port)]

def make_compact_peer_list(peer_list):
    peer_string = b""
    for peer in peer_list:
        ip = inet_aton(peer[1])
        port = pack(">H", int(peer[2]))
        peer_string += (ip + port)
    return peer_string

def make_peer_list(peer_list):
    peers = []
    for peer in peer_list:
        p = {}
        p["peer id"] = peer[0]
        p["ip"] = peer[1]
        p["port"] = int(peer[2])
        peers.append(p)
    return peers

def peer_list(peer_list, compact):
    if compact:
        return make_compact_peer_list(peer_list)
    else:
        return make_peer_list(peer_list)

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        package = decode_request(self.path)
        if not package:
            self.send_error(403)
            return

        info_hash = package["info_hash"][0]
        compact = bool(int(package["compact"][0]))
        ip = self.client_address[0]
        port = package["port"][0]
        peer_id = package["peer_id"][0]
        add_peer(self.server.torrents, info_hash, peer_id, ip, port)

        response = {}
        response["interval"] = self.server.interval
        response["complete"] = 0
        response["incomplete"] = 0
        response["peers"] = make_peer_list(self.server.torrents[info_hash])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(encode(response).encode())

        info("PACKAGE: %s", package)
        info("RESPONSE: %s", response)

    def log_message(self, format, *args):
        return

class Tracker:
    def __init__(self, host="0.0.0.0", port=9999, interval=5, log="tracker.log"):
        self.host = host
        self.port = port
        self.server_class = HTTPServer
        self.httpd = self.server_class((self.host, self.port), RequestHandler)
        self.running = False
        self.server_class.interval = interval

        basicConfig(filename=log, level=INFO)
        self.server_class.torrents = {}

    def runner(self):
        while self.running:
            self.httpd.handle_request()

    def run(self):
        if not self.running:
            self.running = True
            self.thread = Thread(target=self.runner)
            self.thread.start()

    def send_dummy_request(self):
        address = f"http://{self.host}:{self.port}"
        urlopen(address)

    def stop(self):
        if self.running:
            self.running = False
            self.send_dummy_request()
            self.thread.join()

    def __del__(self):
        self.stop()
        self.httpd.server_close()

if __name__ == "__main__":
    tracker = Tracker()
    tracker.run()
