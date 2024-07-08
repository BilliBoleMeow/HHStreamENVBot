from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import base64
from hashlib import sha256

key = 'BHADOO9854752658'
iv =  'CLOUD54158954721'.encode('utf-8')
SECRET_KEY = '647e2c1ac884418b5c270862a9a484105e88b11f097fa9d5ddd09eb4c53737bd'

def verify_sha256_key(cid, fid, expiration_time, sha256_key):
    try:
        # Concatenate the components with the secret key
        data_to_hash = f"{cid}|{fid}|{expiration_time}|{SECRET_KEY}".encode('utf-8')

        # Calculate the SHA-256 hash
        sha256_hash = sha256(data_to_hash).hexdigest()

        # Compare the calculated hash with the received sha256_key
        return sha256_hash == sha256_key
    except Exception:
        return False

def decrypt(enc, key, iv):
    enc = base64.b64decode(enc)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc), 16)
    decrypted_str = decrypted.decode('utf-8')
    channel_id, message_id, expiration_time = decrypted_str.split('|')
    return channel_id, message_id, int(expiration_time)
