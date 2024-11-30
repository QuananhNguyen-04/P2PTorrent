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
def add_peer(torrents, info_hash, peer_id, ip, port, type):
    if info_hash not in torrents:
        torrents[info_hash] = {"seeder": [], "leecher": []}
        torrents[info_hash]["seeder"] = [(peer_id, ip, port)]
    if info_hash in torrents:
        if (peer_id, ip, port) not in torrents[info_hash]:
            torrents[info_hash][type].append((peer_id, ip, port))


def change_peer_role(torrents, info_hash, peer_id, ip, port):
    if info_hash in torrents:
        if (peer_id, ip, port) in torrents[info_hash]["leecher"]:
            torrents[info_hash]["leecher"].remove((peer_id, ip, port))
            torrents[info_hash]["seeder"].append((peer_id, ip, port))


# remove peer from list
def remove_peer(torrents, info_hash, peer_id):
    # in case torrents, torrents[info] are dicts
    # if info_hash in torrents and peer_id in torrents[info_hash]:
    #     del torrents[info_hash][peer_id]
    if info_hash in torrents:
        for key in ["seeder", "leecher"]:
            torrents[info_hash][key] = [
                peer for peer in torrents[info_hash][key] if peer[0] != peer_id
            ]

        # If both seeder and leecher lists are empty, remove the info_hash entry
        if not torrents[info_hash]["seeder"] and not torrents[info_hash]["leecher"]:
            del torrents[info_hash]

# make compact peer list
def make_compact_peer_list(peer_list):
    peer_string = b""
    for peer in peer_list:
        ip = inet_aton(peer[1])
        port = pack(">H", int(peer[2]))
        peer_string += ip + port
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
                if query["left"][0] == "0":
                    add_peer(
                        self.server.torrents, info_hash, peer_id, ip, port, "seeder"
                    )
                elif query["left"][0] != "0":
                    add_peer(
                        self.server.torrents, info_hash, peer_id, ip, port, "leecher"
                    )
                    self.send_response(200)
                    self.end_headers()
                    # self.wfile.write(encode(response).encode())
                info("Peer joined: %s", query)

            elif query["event"][0] == "stopped":
                remove_peer(self.server.torrents, info_hash, peer_id)
                response = {"interval": self.server.interval, "peers": []}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(encode(response).encode())
                info("Peer left: %s", query)
                return
            
            elif query["event"][0] == "completed":
                change_peer_role(self.server.torrents, info_hash, peer_id, ip, port)
                print("changed role", info_hash, peer_id, ip, port)
                self.send_response(200)
                self.end_headers()
                info("Peer completed: %s", query)
                return

        # if (
        #     info_hash not in self.server.torrents
        #     or peer_id not in self.server.torrents[info_hash]
        # ):
        #     add_peer(self.server.torrents, info_hash, peer_id, ip, port)

        response = {}
        response["interval"] = self.server.interval
        response["complete"] = len(self.server.torrents[info_hash]["seeder"])
        response["incomplete"] = len(self.server.torrents[info_hash]["leecher"])
        print(self.server.torrents[info_hash]["seeder"])
        response["peers"] = make_peer_list(self.server.torrents[info_hash]["seeder"])
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
        self.httpd.timeout = 5  # closing tracker supporter
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
