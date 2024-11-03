import hashlib
from bencode import decode

def get_info_hash(torrent_file_path):
    with open(torrent_file_path, 'rb') as f:
        torrent_data = f.read()
    
    torrent_dict = decode(torrent_data)
    info = torrent_dict['info']
    
    # Encode lại dictionary info thành bencode
    info_bencoded = bencode.encode(info)
    
    # Tạo info hash bằng SHA-1
    info_hash = hashlib.sha1(info_bencoded).digest()
    
    return info_hash

# Ví dụ sử dụng
torrent_file_path = '/nam3/computer networking/BTL1/official/peer.torrent'
info_hash = get_info_hash(torrent_file_path)
print(info_hash)
