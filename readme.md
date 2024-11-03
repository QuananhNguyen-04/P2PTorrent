This directory contains a collection of Python files that implement a peer-to-peer file sharing system using the BitTorrent protocol. The system consists of a tracker, peers, and a file transfer mechanism.

### Prerequisites
Python 3.x installed on your system
bencode library installed (pip install bencode)
requests library installed (pip install requests)
### Running the Tracker
Navigate to the tracker.py file in the directory.
Run the tracker by executing python tracker.py in your terminal.
The tracker will start listening on the specified host and port (default is 0.0.0.0:9999).
You can stop the tracker by pressing any key in the terminal.
### Running a Peer
Navigate to the peer.py file in the directory.
Run a peer by executing python peer.py in your terminal.
The peer will start communicating with the tracker and other peers.
### Running the File Transfer Server
Navigate to the file_transfer.py file in the directory.
Run the file transfer server by executing python file_transfer.py in your terminal.
The server will start listening on the specified host and port (default is 192.168.43.7:681).
### Creating a Torrent File
Navigate to the torrent.py file in the directory.
Run the make_torrent_file function by executing python torrent.py in your terminal.
Follow the prompts to create a torrent file.
### Starting a Torrent
Navigate to the torrent.py file in the directory.
Run the run function by executing python torrent.py in your terminal.
Follow the prompts to start the torrent.
### Notes
Make sure to update the tracker_url variable in peer.py to point to the correct tracker host and port.
Make sure to update the torrent_file variable in torrent.py to point to the correct torrent file.
This is a basic implementation of the BitTorrent protocol and may not be suitable for production use.
### Directory Structure
tracker.py: Tracker implementation
peer.py: Peer implementation
file_transfer.py: File transfer server implementation
torrent.py: Torrent file creation and management implementation
makefile.py: Utility functions for creating torrent files
util.py: Utility functions for the system