from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from logging import basicConfig, info, INFO
from socket import inet_aton, gethostbyname, gethostname
from struct import pack
from urllib.parse import parse_qs
from urllib.request import urlopen
from bencode import encode

# decode request path
def decode_path(path):
    path = path[1:] if path.startswith("?") else path[2:]
    return parse_qs(path)

# add peer to list
def add_peer(torrents, info_hash, peer_id, ip, port):
    if info_hash in torrents:
        if (peer_id, ip, port) not in torrents[info_hash]:
            torrents[info_hash].append((peer_id, ip, port))
    else:
        torrents[info_hash] = [(peer_id, ip, port)]

# remove peer from list
def remove_peer(torrents, info_hash, peer_id):
    # in case torrents, torrents[info] are dicts
    # if info_hash in torrents and peer_id in torrents[info_hash]:
    #     del torrents[info_hash][peer_id] 
    if info_hash in torrents:
        torrents[info_hash] = [peer for peer in torrents[info_hash] if peer[0] != peer_id]
        # Find and remove the peer tuple that matches peer_id, ip, and port
        torrents[info_hash] = [
            peer for peer in torrents[info_hash]
            if not (peer[0] == peer_id)
        ]

# make compact peer list
def make_compact_peer_list(peer_list):
    peer_string = b""
    for peer in peer_list:
        ip = inet_aton(peer[1])
        port = pack(">H", int(peer[2]))
        peer_string += (ip + port)
    return peer_string

# make full peer list
def make_peer_list(peer_list):
    peers = []
    for peer in peer_list:
        p = {}
        p["peer id"] = peer[0]
        p["ip"] = peer[1]
        p["port"] = int(peer[2])
        peers.append(p)
    return peers

# get peer list
def get_peer_list(peer_list, compact):
    if compact:
        return make_compact_peer_list(peer_list)
    else:
        return make_peer_list(peer_list)

class TrackerRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = decode_path(self.path)
        if not query:
            self.send_error(403)
            return

        info_hash = query["info_hash"][0]

        ip = self.client_address[0]
        port = query["port"][0]
        peer_id = query["peer_id"][0]
        if "event" in query:
            if query["event"][0] == "started":
                info("Peer joined: %s", query)
            elif query["event"][0] == "stopped":
                remove_peer(self.server.torrents, info_hash, peer_id)
                response = {"interval": self.server.interval, "peers": []}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(encode(response).encode())
                info("Peer left: %s", query)
                return
        if info_hash not in self.server.torrents or peer_id not in self.server.torrents[info_hash]:
            add_peer(self.server.torrents, info_hash, peer_id, ip, port)

        response = {}
        response["interval"] = self.server.interval
        response["complete"] = 0
        response["incomplete"] = 0
        response["peers"] = make_peer_list(self.server.torrents[info_hash])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(encode(response).encode())

        info("PACKAGE: %s", query)
        info("RESPONSE: %s", response)

class Tracker:
    def __init__(self, host="0.0.0.0", port=9999, interval=5, log="tracker.log"):
        self.host = host
        self.port = port
        self.server_class = HTTPServer
        self.httpd = self.server_class((self.host, self.port), TrackerRequestHandler)
        self.running = False
        self.server_class.interval = interval
        self.httpd.timeout = 5 # closing tracker supporter
        basicConfig(filename=log, level=INFO)
        self.server_class.torrents = {}

    def runner(self):
        while self.running:
            self.httpd.handle_request()
    # stop tracker
    def interupt(self):
        input("Press any key to stop tracker... ")
        self.running = False

    def run(self):
        if not self.running:
            # reinitialize torrent per run
            print(f"Starting tracker... at {self.host}:{self.port}")
            self.running = True
            # self.thread = Thread(target=self.runner)
            # add interupt function
            self.input_thread = Thread(target=self.interupt)
            # self.thread.start()
            self.input_thread.start()
            self.runner()

    def send_dummy_request(self):
        address = f"http://{self.host}:{self.port}"
        urlopen(address)

    def stop(self):
        if self.running:
            print(f"Stopping tracker at {self.host}:{self.port}")
            self.running = False
            self.httpd.server_close()

            # self.send_dummy_request() #urlopen is not working
            # self.thread.join()

    def __del__(self):
        self.stop()
        # close interupt thread
        self.input_thread.join()
        self.httpd.server_close()

if __name__ == "__main__":
    host = gethostbyname(gethostname())
    
    tracker = Tracker(host=host)
    tracker.run()
