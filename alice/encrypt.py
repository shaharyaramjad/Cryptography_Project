from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Cryptodome.Cipher import AES
from cryptography.x509 import load_pem_x509_certificate
import os, json

image_file = 'confidential_image.JPG'
file_sent_to_bob = '../bob/encrypted.txt'
alice_signing_key_file = 'alice_signing_key.pem'
bob_public_key_file = 'bob_public_key.crt'

# Open the input file for reading in binary format
f = open(image_file, 'rb')
input_bytes = f.read()
f.close()

# Open the bob certificate file for reading in binary format and extract the public key
f = open(bob_public_key_file, 'rb')
cert = load_pem_x509_certificate(f.read())
f.close()
bob_public_key = cert.public_key()

# Generate a random AES key and IV
aes_key = os.urandom(32)  # 256-bit AES key
iv = os.urandom(16)       # 16-byte means 128 bits IV for AES

# Encrypt the file data using AES algorithm with aes_key, initialisation vector with CFB mode
cipher = AES.new(aes_key, AES.MODE_CFB, iv)
encryptor_data = cipher.encrypt(input_bytes)

# Encrypt the AES key using Bob's RSA public key
encrypted_aes_key = bob_public_key.encrypt(
    aes_key,
    padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
)

# Load Alice's private EC key to sign the data
f = open(alice_signing_key_file, 'rb')
alice_private_key = serialization.load_pem_private_key(f.read(), password=b'alicesecret')
f.close()

# Sign the encrypted data using Alice's EC private key
signature = alice_private_key.sign(
    encryptor_data,
    ec.ECDSA(hashes.SHA256())
)

# Save data in a structured JSON format
f = open(file_sent_to_bob, 'wb')
json_data = {
    'iv': iv.hex(),
    'encrypted_aes_key': encrypted_aes_key.hex(),
    'ciphertext': encryptor_data.hex(),
    'signature': signature.hex()
}
f.write(json.dumps(json_data).encode('utf-8'))
f.close()
print("File encrypted and saved successfully!")