import hashlib
from bencode import decode, encode

def get_info_hash(torrent_file_path):
    # changed from rb to r
    with open(torrent_file_path, 'r') as f:
        torrent_data = f.read()
    torrent_dict = decode(torrent_data)
    info = torrent_dict['info']
    # Encode lại dictionary info thành bencode
    info_bencoded = encode(info)
    # SHA1 needs proper type
    info_bytes = info_bencoded.encode('utf-8')
    # Tạo info hash bằng SHA-1
    info_hash = hashlib.sha1(info_bytes).digest()
    
    return info_hash

# Ví dụ sử dụng
torrent_file_path = './peer.torrent' # Relative path is easier
info_hash = get_info_hash(torrent_file_path)
print(info_hash)
