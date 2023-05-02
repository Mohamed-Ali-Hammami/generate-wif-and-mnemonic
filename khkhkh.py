import ecdsa
import hashlib
import base58
import mnemonic

# Define the generator point for the secp256k1 curve used in Bitcoin
G = ecdsa.SECP256k1.generator

private_key_hex = "5bb09e13498a812b5354ce387124e7971acec311dac92718f0e95a0b82036588"

# Convert the private key from hex to an integer
private_key_int = int(private_key_hex, 16)

# Generate the corresponding public key using the private key
public_key_point = private_key_int * G

# Get the compressed public key in hex format
compressed_public_key_hex = ecdsa.util.string_to_number(b"\x02" + bytes([public_key_point.y() % 2 + 2]) + public_key_point.x().to_bytes(32, byteorder='big'))
hex_pubkey = hex(public_key_point.x())[2:].zfill(64) + hex(public_key_point.y())[2:].zfill(64)

wif_prefix = b'\x80' # use bytes instead of a string for prefix
compressed = True

if compressed:
    hex_pubkey = hex_pubkey + '01' # append a byte to indicate compressed key


# convert hex public key to bytes
public_key_bytes = bytes.fromhex(hex_pubkey)

# add prefix to indicate that this is a compressed public key
public_key_bytes = b'\x02' + public_key_bytes if int(hex_pubkey[-2:], 16) % 2 == 0 else b'\x03' + public_key_bytes

# convert bytes public key to hex
hex_public_key = public_key_bytes.hex()

# convert hex private key to bytes
private_key_bytes = private_key_int.to_bytes(32, byteorder='big')

# add prefix to indicate that this is a private key
private_key_bytes = wif_prefix + private_key_bytes

# calculate checksum using SHA-256 twice
checksum = hashlib.sha256(hashlib.sha256(private_key_bytes).digest()).digest()[:4]

# append checksum to the end of the private key
wif_bytes = private_key_bytes + checksum

# encode the result using base58 encoding
wif = base58.b58encode(wif_bytes)

print('WIF:', wif.decode('utf-8'))

# Convert the private key to a mnemonic phrase
entropy = private_key_int.to_bytes(32, byteorder='big')
mnemonic_phrase = mnemonic.Mnemonic('english').to_mnemonic(entropy)
print('Mnemonic phrase:', mnemonic_phrase)
